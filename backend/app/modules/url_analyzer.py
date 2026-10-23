"""Phishing & malicious-URL analyser.

A deterministic heuristic engine (no external API key required) that scores
a URL on the lexical and structural signals real phishing kits rely on:

* IP-literal hosts, punycode / homograph domains, typosquatting of major
  brands (edit distance), excessive subdomains
* URL shorteners, ``@`` userinfo tricks, double-slash redirects, long URLs
* High-entropy hostnames (DGA-like), suspicious TLDs, brand names in the
  path of an unrelated domain, credential-harvesting keywords
* Non-standard ports, missing HTTPS, encoded/obfuscated characters

Every signal contributes weighted points and is returned as an explainable
finding, because a security tool that cannot explain itself is not trusted.
"""

import ipaddress
import math
import re
from dataclasses import dataclass, field
from urllib.parse import unquote, urlparse

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "loan", "men", "gq", "cf", "tk", "ml", "work", "party", "review", "science", "trade", "date", "faith", "accountant", "download", "racing", "win", "vip", "best", "live"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "t.ly"}
BRANDS = {
    "paypal": "paypal.com", "apple": "apple.com", "microsoft": "microsoft.com",
    "google": "google.com", "amazon": "amazon.com", "netflix": "netflix.com",
    "facebook": "facebook.com", "instagram": "instagram.com", "whatsapp": "whatsapp.com",
    "sbi": "sbi.co.in", "hdfc": "hdfcbank.com", "icici": "icicibank.com",
    "paytm": "paytm.com", "phonepe": "phonepe.com", "upi": "npci.org.in",
}
PHISH_KEYWORDS = [
    "verify", "login", "signin", "secure", "account", "update", "confirm",
    "password", "banking", "wallet", "suspended", "unlock", "recover",
    "kyc", "otp", "claim", "prize", "free", "bonus",
]


def _levenshtein(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 99
    dp = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        prev, dp[0] = dp[0], i
        for j, cb in enumerate(b, 1):
            prev, dp[j] = dp[j], min(dp[j] + 1, dp[j - 1] + 1, prev + (ca != cb))
    return dp[-1]


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {c: text.count(c) / len(text) for c in set(text)}
    return -sum(p * math.log2(p) for p in freq.values())


@dataclass
class UrlReport:
    url: str
    risk_score: int
    verdict: str
    findings: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "url": self.url, "risk_score": self.risk_score,
            "verdict": self.verdict, "findings": self.findings,
        }


def _verdict(score: int) -> str:
    if score >= 70:
        return "malicious"
    if score >= 40:
        return "suspicious"
    if score >= 20:
        return "low-risk"
    return "safe"


def analyze_url(raw_url: str) -> UrlReport:
    url = raw_url.strip()
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    findings: list[dict] = []
    score = 0

    def add(points: int, code: str, message: str) -> None:
        nonlocal score
        score += points
        findings.append({"points": points, "code": code, "message": message})

    if not host:
        add(50, "unparseable", "The URL has no host and cannot be trusted or visited safely.")

    if parsed.scheme != "https":
        add(15, "no-https", "No HTTPS — traffic (and any password typed here) is not encrypted.")

    try:
        ipaddress.ip_address(host)
        add(35, "ip-host", "Host is a raw IP address — a classic phishing / malware-delivery pattern.")
    except ValueError:
        pass

    if host.startswith("xn--") or ".xn--" in host:
        add(30, "punycode", "Punycode domain — often used for homograph attacks that imitate real brands.")

    labels = host.split(".") if host else []
    if len(labels) > 4:
        add(15, "many-subdomains", f"{len(labels)} domain labels — deep subdomains are used to hide the real owner.")
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        add(15, "suspicious-tld", f"The .{tld} TLD is heavily abused for phishing and malware campaigns.")

    registrable = ".".join(labels[-2:]) if len(labels) >= 2 else host
    sld = labels[-2] if len(labels) >= 2 else ""
    # Leet-speak normalisation exposes paypa1 / g00gle style imitations.
    leet = host.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"}))
    # Typosquatters hide behind hyphenated padding (paypa1-secure-login), so
    # compare both the full SLD and each hyphen-separated token.
    candidates = {sld, *sld.split("-")} if sld else set()
    for brand, official in BRANDS.items():
        if (brand in host or brand in leet) and registrable != official and not host.endswith("." + official):
            add(35, "brand-in-host", f"Domain imitates '{brand}' but is not the official {official}.")
        elif any(c and c != brand and _levenshtein(c, brand) in (1, 2) for c in candidates) and len(brand) >= 4:
            add(30, "typosquat", f"Domain '{sld}' is a near-miss spelling of '{brand}' (typosquatting).")

    if host in SHORTENERS:
        add(20, "shortener", "URL shortener — the real destination is hidden until clicked.")

    if "@" in parsed.netloc:
        add(30, "userinfo-trick", "Contains '@' in the address — browsers ignore everything before it, hiding the real host.")
    if "//" in parsed.path:
        add(10, "double-slash", "Double slash in the path — often used as an open-redirect / obfuscation trick.")
    if parsed.port and parsed.port not in (80, 443):
        add(15, "odd-port", f"Non-standard port {parsed.port} — legitimate public sites rarely need one.")

    path_query = unquote(f"{parsed.path} {parsed.query}").lower()
    hits = [kw for kw in PHISH_KEYWORDS if kw in path_query]
    brand_in_path = [b for b in BRANDS if b in path_query and b not in host]
    if brand_in_path:
        add(20, "brand-in-path", f"Page path name-drops {', '.join(brand_in_path)} on an unrelated domain.")
    if len(hits) >= 2:
        add(15, "phish-keywords", f"Credential / urgency keywords in the URL: {', '.join(sorted(set(hits)))}.")

    if len(url) > 100:
        add(10, "very-long", f"URL is {len(url)} characters — long URLs hide the destination and payload.")
    if _entropy(sld) > 3.4 and len(sld) >= 8:
        add(10, "high-entropy-host", "Hostname looks algorithmically generated (high entropy), like DGA malware domains.")
    if re.search(r"%[0-9a-fA-F]{2}", parsed.path) and parsed.path.count("%") >= 3:
        add(10, "encoded-path", "Heavily percent-encoded path — used to smuggle payloads past filters.")
    if "-" in sld and sld.count("-") >= 2:
        add(5, "hyphen-stuffing", "Multiple hyphens in the domain — common in look-alike phishing domains.")

    score = min(score, 100)
    if not findings:
        findings.append({"points": 0, "code": "clean", "message": "No phishing or malware-delivery signals detected."})
    return UrlReport(url=raw_url, risk_score=score, verdict=_verdict(score), findings=findings)
