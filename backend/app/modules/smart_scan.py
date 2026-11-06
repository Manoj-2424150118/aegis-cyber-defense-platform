"""Smart Scan — one box for anything a visitor pastes.

People who receive something suspicious rarely know whether it is "a
URL", "an email" or "a message" — they just have the thing itself.
Smart Scan classifies the pasted content, routes it to the right
existing engine (Link Checker, Email Analyser or Message Checker) and
wraps the result in one envelope, so the UI can render a verdict
without knowing — or asking — which tool ran.

Classification is deliberately conservative and deterministic:
- a single whitespace-free token that parses as a host/URL is a link;
- text whose leading lines look like RFC 5322 headers is an email;
- everything else is treated as a message (the Message Checker also
  extracts and scores any links inside the text, so a scam SMS that
  carries a link is still fully analysed).
"""

import re

from app.modules import email_analyzer, message_analyzer, url_analyzer
from app.validation import host_from_url, is_valid_host

_HEADER_LINE = re.compile(
    r"^(from|to|subject|date|received|return-path|reply-to|cc|bcc|"
    r"mime-version|content-type|content-transfer-encoding|message-id|"
    r"dkim-signature|authentication-results|x-[a-z0-9-]+)\s*:",
    re.IGNORECASE,
)

_TOOL_LABELS = {
    "url": "Link Checker",
    "email": "Email Analyser",
    "message": "Message Checker",
}

_TYPE_LABELS = {
    "url": "a link",
    "email": "an email",
    "message": "a message",
}


def _looks_like_single_url(text: str) -> bool:
    if any(c.isspace() for c in text):
        return False
    # A bare token containing "@" without a scheme is an email address
    # (or a credential), never a link — host_from_url would happily
    # read "user@example.com" as userinfo + host.
    if "@" in text and "://" not in text:
        return False
    host = host_from_url(text)
    return bool(host) and is_valid_host(host) and "." in host


def split_email(text: str) -> tuple[str, str]:
    """Split pasted email text into (headers, body).

    Headers are the leading block of RFC-style header lines (including
    folded continuation lines); the body is everything after them. When
    no header block is present the whole text is the body.
    """
    lines = text.splitlines()
    header_lines: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if _HEADER_LINE.match(line) or (header_lines and line[:1] in (" ", "\t")):
            header_lines.append(line)
            i += 1
            continue
        break
    if not header_lines:
        return "", text
    rest = lines[i:]
    if rest and not rest[0].strip():
        rest = rest[1:]
    return "\n".join(header_lines), "\n".join(rest)


def classify_input(text: str) -> str:
    """Return "url", "email" or "message" for pasted content."""
    stripped = text.strip()
    if _looks_like_single_url(stripped):
        return "url"
    lines = stripped.splitlines()
    header_hits = sum(1 for line in lines[:12] if _HEADER_LINE.match(line))
    if header_hits >= 2:
        return "email"
    # A lone leading header line ("From: …") followed by more text is a
    # pasted email whose remaining headers were trimmed — still email.
    if len(lines) > 1 and lines and _HEADER_LINE.match(lines[0]):
        return "email"
    return "message"


def smart_scan(text: str) -> dict:
    """Classify *text*, run the matching engine, return one envelope."""
    stripped = text.strip()
    kind = classify_input(stripped)
    if kind == "url":
        result = url_analyzer.analyze_url(stripped).as_dict()
    elif kind == "email":
        headers, body = split_email(stripped)
        result = email_analyzer.analyze_email(headers, body)
    else:
        result = message_analyzer.analyze_message(stripped)
    return {
        "detected_type": kind,
        "detected_label": _TYPE_LABELS[kind],
        "tool": _TOOL_LABELS[kind],
        "verdict": result["verdict"],
        "risk_score": result["risk_score"],
        "result": result,
    }
