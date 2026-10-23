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


class _UrlContext:
    """Mutable analysis state shared by the URL stages."""

    def __init__(self, raw_url: str):
        self.raw_url = raw_url
        url = raw_url.strip()
        if "://" not in url:
            url = "http://" + url
        self.url = url
        self.parsed = urlparse(url)
        self.host = (self.parsed.hostname or "").lower()
        self.labels = self.host.split(".") if self.host else []
        self.sld = self.labels[-2] if len(self.labels) >= 2 else ""
        self.findings: list[dict] = []
        self.score = 0

    def add(self, points: int, code: str, message: str) -> None:
        self.score += points
        self.findings.append({"points": points, "code": code, "message": message})


def _stage_parse(ctx: _UrlContext) -> None:
    if not ctx.host:
        ctx.add(50, "unparseable", "The URL has no host and cannot be trusted or visited safely.")


def _stage_transport(ctx: _UrlContext) -> None:
    if ctx.parsed.scheme != "https":
        ctx.add(15, "no-https", "No HTTPS — traffic (and any password typed here) is not encrypted.")
    try:
        port = ctx.parsed.port
    except ValueError:
        # e.g. "javascript:alert(1)" mangled into a host:port shape — the
        # port property raises instead of returning None. Never 500 on input.
        port = None
        ctx.add(20, "malformed-port", "The URL's port is not a number — the address is malformed or disguised.")
    if port and port not in (80, 443):
        ctx.add(15, "odd-port", f"Non-standard port {port} — legitimate public sites rarely need one.")


def _stage_host(ctx: _UrlContext) -> None:
    host, labels = ctx.host, ctx.labels
    try:
        ipaddress.ip_address(host)
        ctx.add(35, "ip-host", "Host is a raw IP address — a classic phishing / malware-delivery pattern.")
    except ValueError:
        pass
    if host.startswith("xn--") or ".xn--" in host:
        ctx.add(30, "punycode", "Punycode domain — often used for homograph attacks that imitate real brands.")
    if len(labels) > 4:
        ctx.add(15, "many-subdomains", f"{len(labels)} domain labels — deep subdomains are used to hide the real owner.")
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        ctx.add(15, "suspicious-tld", f"The .{tld} TLD is heavily abused for phishing and malware campaigns.")
    if host in SHORTENERS:
        ctx.add(20, "shortener", "URL shortener — the real destination is hidden until clicked.")
    if _entropy(ctx.sld) > 3.4 and len(ctx.sld) >= 8:
        ctx.add(10, "high-entropy-host", "Hostname looks algorithmically generated (high entropy), like DGA malware domains.")
    if "-" in ctx.sld and ctx.sld.count("-") >= 2:
        ctx.add(5, "hyphen-stuffing", "Multiple hyphens in the domain — common in look-alike phishing domains.")


def _stage_brand(ctx: _UrlContext) -> None:
    host, labels, sld = ctx.host, ctx.labels, ctx.sld
    registrable = ".".join(labels[-2:]) if len(labels) >= 2 else host
    # Leet-speak normalisation exposes paypa1 / g00gle style imitations.
    leet = host.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"}))
    # Typosquatters hide behind hyphenated padding (paypa1-secure-login), so
    # compare both the full SLD and each hyphen-separated token.
    candidates = {sld, *sld.split("-")} if sld else set()
    for brand, official in BRANDS.items():
        if (brand in host or brand in leet) and registrable != official and not host.endswith("." + official):
            ctx.add(35, "brand-in-host", f"Domain imitates '{brand}' but is not the official {official}.")
        elif any(c and c != brand and _levenshtein(c, brand) in (1, 2) for c in candidates) and len(brand) >= 4:
            ctx.add(30, "typosquat", f"Domain '{sld}' is a near-miss spelling of '{brand}' (typosquatting).")


def _stage_path(ctx: _UrlContext) -> None:
    parsed = ctx.parsed
    if "@" in parsed.netloc:
        ctx.add(30, "userinfo-trick", "Contains '@' in the address — browsers ignore everything before it, hiding the real host.")
    if "//" in parsed.path:
        ctx.add(10, "double-slash", "Double slash in the path — often used as an open-redirect / obfuscation trick.")
    path_query = unquote(f"{parsed.path} {parsed.query}").lower()
    hits = [kw for kw in PHISH_KEYWORDS if kw in path_query]
    brand_in_path = [b for b in BRANDS if b in path_query and b not in ctx.host]
    if brand_in_path:
        ctx.add(20, "brand-in-path", f"Page path name-drops {', '.join(brand_in_path)} on an unrelated domain.")
    if len(hits) >= 2:
        ctx.add(15, "phish-keywords", f"Credential / urgency keywords in the URL: {', '.join(sorted(set(hits)))}.")
    if len(ctx.url) > 100:
        ctx.add(10, "very-long", f"URL is {len(ctx.url)} characters — long URLs hide the destination and payload.")
    if re.search(r"%[0-9a-fA-F]{2}", parsed.path) and parsed.path.count("%") >= 3:
        ctx.add(10, "encoded-path", "Heavily percent-encoded path — used to smuggle payloads past filters.")


URL_STAGES = [
    ("Parsing the address", _stage_parse),
    ("Transport security — HTTPS & port", _stage_transport),
    ("Host reputation — IP, punycode, TLD, entropy", _stage_host),
    ("Brand impersonation & typosquatting", _stage_brand),
    ("Path & payload heuristics", _stage_path),
]


def iter_url_stages(raw_url: str):
    """Yield ``(stage_label, new_findings, running_score)`` as each stage
    genuinely executes — this powers the live agent view in the UI."""
    ctx = _UrlContext(raw_url)
    for label, stage in URL_STAGES:
        before = len(ctx.findings)
        stage(ctx)
        yield label, ctx.findings[before:], min(ctx.score, 100)
    return ctx


def analyze_url(raw_url: str) -> UrlReport:
    gen = iter_url_stages(raw_url)
    ctx = None
    while True:
        try:
            next(gen)
        except StopIteration as stop:
            ctx = stop.value
            break
    score = min(ctx.score, 100)
    findings = list(ctx.findings)
    if not findings:
        findings.append({"points": 0, "code": "clean", "message": "No phishing or malware-delivery signals detected."})
    return UrlReport(url=raw_url, risk_score=score, verdict=_verdict(score), findings=findings)
