"""Phishing-email analyser — headers + content.

Parses ``Authentication-Results`` (SPF / DKIM / DMARC), compares the
visible From domain against Return-Path / Reply-To, detects display-name
spoofing and homograph domains, and scores the body for urgency, credential
requests and link/display mismatches — the social-engineering patterns
behind Business Email Compromise (BEC).
"""

import re
from urllib.parse import urlparse

from app.modules.url_analyzer import analyze_url

URGENCY = [
    "urgent", "immediately", "act now", "within 24 hours", "account will be closed",
    "suspended", "verify now", "final warning", "unusual activity", "confirm your",
    "payment failed", "wire transfer", "gift card", "keep this confidential",
    "do not tell", "kindly do the needful", "revalidate", "expires today",
]
CREDENTIAL_BAIT = ["enter your password", "confirm your password", "your otp", "share the code", "cvv", "pin number", "bank details", "card number"]
FREE_MAIL = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "proton.me", "protonmail.com", "yandex.com", "mail.ru"}


def _domain(addr: str) -> str:
    m = re.search(r"@([a-zA-Z0-9.\-]+)", addr or "")
    return m.group(1).lower() if m else ""


def _header(headers: str, name: str) -> str:
    m = re.search(rf"^{re.escape(name)}:\s*(.+)$", headers, re.I | re.M)
    return m.group(1).strip() if m else ""


def analyze_email(raw_headers: str, body: str = "") -> dict:
    findings: list[dict] = []
    score = 0

    def add(points: int, code: str, message: str) -> None:
        nonlocal score
        score += points
        findings.append({"points": points, "code": code, "message": message})

    auth = _header(raw_headers, "Authentication-Results").lower()
    for mech in ("spf", "dkim", "dmarc"):
        if f"{mech}=fail" in auth or f"{mech}=softfail" in auth:
            add(25, f"{mech}-fail", f"{mech.upper()} authentication FAILED — the sender could not prove it owns the domain.")
        elif f"{mech}=" not in auth and raw_headers.strip():
            add(8, f"{mech}-missing", f"No {mech.upper()} result in the headers — legitimacy cannot be verified.")

    from_hdr = _header(raw_headers, "From")
    from_domain = _domain(from_hdr)
    reply_to = _domain(_header(raw_headers, "Reply-To"))
    return_path = _domain(_header(raw_headers, "Return-Path"))
    if reply_to and from_domain and reply_to != from_domain:
        add(25, "reply-to-mismatch", f"Replies go to {reply_to}, not the sender's domain {from_domain} — a classic BEC trick.")
    if return_path and from_domain and return_path != from_domain and not return_path.endswith("." + from_domain):
        add(15, "return-path-mismatch", f"Return-Path domain {return_path} differs from From domain {from_domain}.")
    display = re.match(r'^"?([^"<@]+)"?\s*<', from_hdr)
    if display:
        name = display.group(1).lower()
        for brand in ("paypal", "amazon", "microsoft", "apple", "bank", "support", "security team", "it department", "ceo", "director"):
            if brand in name and brand not in from_domain:
                add(20, "display-name-spoof", f"Display name claims '{display.group(1).strip()}' but the real domain is {from_domain or 'unknown'}.")
                break
    if from_domain in FREE_MAIL and any(w in (display.group(1).lower() if display else "") for w in ("bank", "support", "official", "team")):
        add(15, "freemail-impersonation", "An 'official'-sounding sender is using a free webmail address.")
    if any(label.startswith("xn--") for label in from_domain.split(".")):
        add(25, "homograph-domain", "Sender domain uses punycode — possible homograph impersonation of a real brand.")

    text = (body or "").lower()
    urgency_hits = [u for u in URGENCY if u in text]
    if len(urgency_hits) >= 2:
        add(20, "urgency-pressure", f"Pressure tactics detected: {', '.join(urgency_hits[:4])}. Real banks don't rush you like this.")
    elif urgency_hits:
        add(8, "urgency-language", f"Urgency language detected: {urgency_hits[0]}.")
    bait = [b for b in CREDENTIAL_BAIT if b in text]
    if bait:
        add(30, "credential-bait", f"Message asks for secrets it must never have: {', '.join(bait)}. No legitimate service does this.")

    link_scores = []
    for href, label in re.findall(r'<a[^>]+href="([^"]+)"[^>]*>([^<]*)</a>', body or "", re.I):
        domain_in_label = _domain(label) or (urlparse(label if "://" in label else "http://" + label).hostname if "." in label else None)
        host = urlparse(href).hostname
        if domain_in_label and host and domain_in_label != host:
            add(25, "link-text-mismatch", f"Link text shows {domain_in_label} but actually leads to {host}.")
        link_scores.append(analyze_url(href).risk_score)
    bare_urls = re.findall(r"https?://[^\s\"'<>]+", body or "")
    for u in bare_urls:
        link_scores.append(analyze_url(u).risk_score)
    if link_scores and max(link_scores) >= 70:
        add(25, "malicious-link", "The email contains a link the URL analyser rates as malicious.")
    elif link_scores and max(link_scores) >= 40:
        add(12, "suspicious-link", "The email contains a link the URL analyser rates as suspicious.")

    score = min(score, 100)
    verdict = "malicious" if score >= 70 else "suspicious" if score >= 40 else "low-risk" if score >= 20 else "likely-safe"
    if not findings:
        findings.append({"points": 0, "code": "clean", "message": "No phishing signals detected in headers or content."})
    return {"risk_score": score, "verdict": verdict, "from_domain": from_domain, "findings": findings}
