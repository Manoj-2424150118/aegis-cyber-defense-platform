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
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import parse_qs, parse_qsl, unquote, urlencode, urlparse, urlunparse

from app.modules.detection import enrich
from app.modules.remediation import fix_for

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "loan", "men", "gq", "cf", "tk", "ml", "work", "party", "review", "science", "trade", "date", "faith", "accountant", "download", "racing", "win", "vip", "best", "live", "sbs", "cyou", "bond", "cfd", "quest"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "t.ly"}
BRANDS = {
    "paypal": "paypal.com", "apple": "apple.com", "microsoft": "microsoft.com",
    "google": "google.com", "amazon": "amazon.com", "netflix": "netflix.com",
    "facebook": "facebook.com", "instagram": "instagram.com", "whatsapp": "whatsapp.com",
    "sbi": "sbi.co.in", "hdfc": "hdfcbank.com", "icici": "icicibank.com",
    "paytm": "paytm.com", "phonepe": "phonepe.com", "upi": "npci.org.in",
}
# Query parameters whose only job is to track the clicker across sites.
# They carry no content, so the report names them and offers a cleaned
# URL with them stripped.
TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_name", "fbclid", "gclid", "dclid", "gbraid", "wbraid",
    "msclkid", "ttclid", "twclid", "li_fat_id", "igshid", "igsh", "yclid",
    "mc_cid", "mc_eid", "_ga", "_gl", "_hsenc", "_hsmi", "hsctatracking",
    "vero_id", "vero_conv", "wickedid", "oly_anon_id", "oly_enc_id",
    "rb_clickid", "s_cid", "ref_src", "ref_url", "spm", "scm", "icid",
    "mkt_tok", "elqtrackid", "trk_contact", "trk_msg", "trk_module",
}
# Hosts that exist to wrap a real destination in a tracking redirect —
# social link shims and marketing-email click trackers. The destination
# the user sees is not the destination they reach.
TRACKING_WRAPPERS = {
    "l.facebook.com", "lm.facebook.com", "l.instagram.com",
    "click.mailchimp.com", "mailchi.mp", "track.customer.io",
    "links.iterable.com", "ct.sendgrid.net", "u.ct.sendgrid.net",
    "trk.klaviyomail.com", "click.pstmrk.it",
    "links.marketo.net", "click.hs-analytics.net", "t.hsms03.com",
}
# Free hosting abused as phishing infrastructure: a brand or credential
# lure hosted here inherits none of the platform's trust.
FREE_HOSTS = {
    "github.io", "pages.dev", "vercel.app", "netlify.app", "weebly.com",
    "wixsite.com", "blogspot.com", "wordpress.com", "glitch.me", "surge.sh",
    "firebaseapp.com", "web.app", "azurewebsites.net", "herokuapp.com",
    "repl.co", "replit.app", "onrender.com", "fly.dev", "streamlit.app",
}
# Zero-width and bidi-control characters: invisible in every UI, but
# they change what a URL actually is — a filter-evasion staple.
_INVISIBLE = dict.fromkeys(
    [ord(c) for c in "\u200b\u200c\u200d\ufeff\u202a\u202b\u202c\u202d\u202e\u2060\u00ad"], None)


# Characters browsers silently delete from URLs before parsing —
# including inside the scheme, which is how "java\tscript:" slips past
# filters that look for the literal word while the browser still runs it.
_BROWSER_STRIPPED = dict.fromkeys([0x09, 0x0A, 0x0D], None)


def _normalize(text: str) -> str:
    """NFKC + strip invisible characters, so analysis sees the URL the
    browser will navigate to — not the disguised one a filter saw."""
    return unicodedata.normalize("NFKC", text.translate(_INVISIBLE).translate(_BROWSER_STRIPPED))


# Latin look-alikes from other scripts (Cyrillic / Greek / Armenian /
# Cherokee). A label built from these can *render* exactly like a brand
# name while being a different, attacker-owned domain. The skeleton of
# a label is what it looks like; comparing skeletons to brand names
# catches the pure-foreign-script homographs that a mixed-script check
# alone misses.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "к": "k", "м": "m", "н": "h", "т": "t", "в": "b", "ѕ": "s", "і": "i",
    "ј": "j", "ԁ": "d", "г": "r", "п": "n", "α": "a", "β": "b", "ε": "e",
    "η": "n", "ι": "i", "κ": "k", "μ": "u", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "χ": "x", "ω": "w", "ᴀ": "a", "ƅ": "b",
    "ƈ": "c", "ƌ": "d", "ɛ": "e", "ɡ": "g", "ɦ": "h", "ɩ": "i", "Ɩ": "i",
    "ʅ": "l", "ɱ": "m", "ɳ": "n", "ʘ": "o", "ʈ": "t", "ʊ": "u", "ʋ": "v",
    "ʏ": "y", "ᴢ": "z",
})


def _skeleton(text: str) -> str:
    """The Latin skeleton of a label — what it visually impersonates."""
    return text.translate(_CONFUSABLES)


def _scripts(text: str) -> set[str]:
    found: set[str] = set()
    for ch in text:
        o = ord(ch)
        if "a" <= ch <= "z" or 0x00C0 <= o <= 0x024F:
            found.add("latin")
        elif 0x0400 <= o <= 0x04FF:
            found.add("cyrillic")
        elif 0x0370 <= o <= 0x03FF:
            found.add("greek")
        elif 0x0590 <= o <= 0x05FF:
            found.add("hebrew")
        elif 0x0600 <= o <= 0x06FF:
            found.add("arabic")
    return found


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
    trackers: list[dict] = field(default_factory=list)
    cleaned_url: str | None = None
    duration_ms: int = 0

    def as_dict(self) -> dict:
        return enrich({
            "url": self.url, "risk_score": self.risk_score,
            "verdict": self.verdict, "findings": self.findings,
            "trackers": self.trackers, "cleaned_url": self.cleaned_url,
        }, "url", duration_ms=self.duration_ms)


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
        raw_url = _normalize(raw_url)
        lowered = raw_url.strip().lower()
        self.dangerous_scheme = next(
            (s for s in ("javascript:", "data:", "vbscript:", "file:", "blob:") if lowered.startswith(s)), None
        )
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
        self.trackers: list[dict] = []
        self.cleaned_url: str | None = None

    def add(self, points: int, code: str, message: str) -> None:
        self.score += points
        self.findings.append({"points": points, "code": code, "message": message, "fix": fix_for(code)})


def _stage_parse(ctx: _UrlContext) -> None:
    if ctx.dangerous_scheme:
        ctx.add(35, "dangerous-scheme", f"The link uses the '{ctx.dangerous_scheme}' scheme — it can execute script or render a fake page locally instead of visiting a website.")
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
    # IPs disguised as numbers dodge blocklists: http://2130706433/ is
    # 127.0.0.1, http://0x7f000001/ and http://0177.0.0.1/ are the same.
    obfuscated = False
    if host.isdigit() and 0 < int(host) <= 4294967295:
        obfuscated = True
    elif host.startswith("0x") and all(c in "0123456789abcdef" for c in host[2:]):
        obfuscated = True
    elif len(labels) == 4 and all(p.isdigit() for p in labels) and any(len(p) > 1 and p.startswith("0") for p in labels):
        obfuscated = True
    if obfuscated:
        ctx.add(35, "obfuscated-ip", "Host is an IP address disguised in numeric/hex/octal form — a blocklist-evasion trick.")
    if host.startswith("xn--") or ".xn--" in host:
        ctx.add(30, "punycode", "Punycode domain — often used for homograph attacks that imitate real brands.")
    if any(ord(c) > 127 for c in host):
        ctx.add(25, "unicode-host", "The domain contains non-ASCII characters — it may be a homograph look-alike that merely *renders* like a real brand.")
        if len(_scripts(host)) >= 2:
            ctx.add(30, "mixed-script-host", "The domain mixes writing systems (e.g. Latin + Cyrillic) — a textbook homograph attack: the characters look Latin but are not.")
    if any(host == fh or host.endswith("." + fh) for fh in FREE_HOSTS):
        lure = [kw for kw in PHISH_KEYWORDS if kw in host]
        if lure:
            ctx.add(20, "free-host-abuse", f"Credential-lure wording ({', '.join(sorted(set(lure)))}) hosted on a free hosting platform — a disposable phishing page pattern: free to create, quick to abandon.")
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
    # Homograph via confusable skeleton: a label that is not the brand
    # in codepoints but *renders* as the brand (e.g. Cyrillic р, а, у
    # spelling "paypal"). The mixed-script check misses labels written
    # entirely in one foreign script, so compare skeletons explicitly.
    if registrable and sld:
        skeleton = _skeleton(sld)
        if skeleton != sld:
            for brand, official in BRANDS.items():
                if skeleton == brand and registrable != official and not host.endswith("." + official):
                    ctx.add(30, "homograph-host", f"Domain '{sld}' is built from look-alike foreign-script characters that render as '{brand}' — a homograph impersonation of {official}.")
                    break


def _stage_path(ctx: _UrlContext) -> None:
    parsed = ctx.parsed
    if "@" in parsed.netloc:
        ctx.add(30, "userinfo-trick", "Contains '@' in the address — browsers ignore everything before it, hiding the real host.")
    if parsed.password:
        ctx.add(20, "embedded-credentials", "The address embeds a username AND password (user:pass@host) — no legitimate link needs credentials baked into it; they are there to disguise the destination or bypass a login gate.")
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
    if "%25" in parsed.path:
        ctx.add(10, "double-encoded", "The path is double-encoded (%25…) — each decode layer hides the real payload from a different filter.")
    path_lower = parsed.path.lower()
    if path_lower.endswith((".exe", ".msi", ".apk", ".dmg", ".scr", ".bat", ".cmd", ".jar", ".hta")):
        ctx.add(25, "executable-download", "This link downloads a program file — message links are the #1 malware delivery route.")
    elif path_lower.endswith((".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img")):
        ctx.add(10, "archive-download", "This link downloads an archive/image file — a common wrapper for hiding malware.")
    params = parse_qs(parsed.query)
    redirect_keys = {"url", "redirect", "redirect_url", "next", "dest", "destination", "target", "return", "returnurl", "continue"}
    if any(k.lower() in redirect_keys and any(v.startswith(("http://", "https://", "//")) for v in vals) for k, vals in params.items()):
        ctx.add(15, "redirect-param", "URL carries an open-redirect parameter — the first page can bounce you somewhere else entirely.")


def _stage_trackers(ctx: _UrlContext) -> None:
    """Trackers & redirect wrappers: who else learns about the click?

    Tracking parameters don't make a link malicious, but they do leak
    the click to ad networks — and on a phishing link they are how the
    operator knows the bait worked. The report names every tracker and
    builds a cleaned URL with the tracking parameters stripped.
    """
    parsed = ctx.parsed
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    tracking = [(k, v) for k, v in pairs if k.lower() in TRACKING_PARAMS or k.lower().startswith("utm_")]
    if tracking:
        names = sorted({k for k, _ in tracking})
        for name in names:
            ctx.trackers.append({"type": "parameter", "name": name})
        ctx.add(5, "tracking-params", f"Link carries {len(names)} tracking parameter(s) — {', '.join(names[:6])} — that report your click to marketing/ad networks. A cleaned link is provided below.")
        kept = [(k, v) for k, v in pairs if not (k.lower() in TRACKING_PARAMS or k.lower().startswith("utm_"))]
        ctx.cleaned_url = urlunparse(parsed._replace(query=urlencode(kept)))
    if ctx.host in TRACKING_WRAPPERS or parsed.path.startswith("/slink"):
        ctx.trackers.append({"type": "redirect-wrapper", "name": ctx.host})
        ctx.add(10, "tracking-wrapper", f"This link routes through {ctx.host}, a tracking redirect service — the destination you see is not the destination you reach, and the operator logs your click.")
    # Wrapped destinations: google.com/url?q=…, facebook l.php?u=… hide
    # the real target inside a parameter of a trusted-looking domain.
    params = parse_qs(parsed.query)
    for key in ("q", "u", "url", "target"):
        for value in params.get(key, []):
            decoded = unquote(value)
            if decoded.startswith(("http://", "https://")) and urlparse(decoded).hostname not in (None, "", ctx.host):
                inner = urlparse(decoded).hostname
                ctx.trackers.append({"type": "wrapped-destination", "name": inner or ""})
                ctx.add(10, "wrapped-destination", f"The visible address is a wrapper — the link actually leads to {inner}. Always judge the final destination, not the wrapper.")
                return


URL_STAGES = [
    ("Parsing the address", _stage_parse),
    ("Transport security — HTTPS & port", _stage_transport),
    ("Host reputation — IP, punycode, TLD, entropy", _stage_host),
    ("Brand impersonation & typosquatting", _stage_brand),
    ("Path & payload heuristics", _stage_path),
    ("Trackers & redirect wrappers", _stage_trackers),
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
    import time
    started = time.perf_counter()
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
        findings.append({"points": 0, "code": "clean", "message": "No phishing or malware-delivery signals detected.", "fix": fix_for("clean")})
    return UrlReport(url=raw_url, risk_score=score, verdict=_verdict(score), findings=findings,
                     trackers=ctx.trackers, cleaned_url=ctx.cleaned_url,
                     duration_ms=int((time.perf_counter() - started) * 1000))


def impersonated_brand(raw_url: str) -> str | None:
    """The brand a URL imitates, if any — used for privacy-safe trend
    statistics (brand names only, never the full URL)."""
    url = raw_url.strip()
    if "://" not in url:
        url = "http://" + url
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return None
    labels = host.split(".")
    registrable = ".".join(labels[-2:]) if len(labels) >= 2 else host
    leet = host.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"}))
    sld = labels[-2] if len(labels) >= 2 else ""
    candidates = {sld, *sld.split("-")} if sld else set()
    for brand, official in BRANDS.items():
        if registrable == official or host.endswith("." + official):
            continue
        if brand in host or brand in leet:
            return brand
        if len(brand) >= 4 and any(c and c != brand and _levenshtein(c, brand) in (1, 2) for c in candidates):
            return brand
    return None


def registrable_domain(raw_url: str) -> str | None:
    """Last two host labels (paypa1-secure.xyz) — the most that trend
    statistics may store about a checked link.

    Strict on purpose: only a syntactically valid *domain* qualifies.
    IP literals, scheme junk (``javascript:…``), fragments and partial
    quads (``10.5``) return ``None`` — storing them as "domains" would
    corrupt the public trends feed."""
    from app.validation import is_valid_domain

    url = raw_url.strip()
    if "://" not in url:
        url = "http://" + url
    host = (urlparse(url).hostname or "").lower()
    if not host or not is_valid_domain(host):
        return None
    labels = host.split(".")
    return ".".join(labels[-2:])
