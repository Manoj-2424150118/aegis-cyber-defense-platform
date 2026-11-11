"""Secret scanner — find leaked credentials in pasted text.

People paste config files, code snippets, logs and .env dumps into
chats, gists and tickets every day — with live keys inside them. This
engine recognises provider credential formats (AWS, GitHub, Slack,
Stripe, SendGrid, Google), private-key blocks, credentialed database
URIs, JWTs, Luhn-valid card numbers and generic high-entropy secret
assignments.

Safety contract: the secret itself is NEVER returned, logged or
stored. Findings carry only a masked form (first 4 / last 2 chars),
and scoring runs on the detection core's noisy-OR model — one leaked
key is bad; independent kinds of leakage compound.
"""

import math
import re

from app.modules.detection import enrich, score_signals
from app.modules.remediation import fix_for

# (code, regex, weight, confidence, deterministic, label)
_PATTERNS: list[tuple[str, re.Pattern, float, float, bool, str]] = [
    ("secret-private-key",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----"),
     0.85, 0.99, True, "Private key"),
    ("secret-aws-key",
     re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
     0.80, 0.97, True, "AWS access key ID"),
    ("secret-github-token",
     re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{22,255}\b"),
     0.80, 0.97, True, "GitHub token"),
    ("secret-stripe-key",
     re.compile(r"\b[rs]k_live_[A-Za-z0-9]{16,}\b"),
     0.80, 0.96, True, "Stripe live secret key"),
    ("secret-db-uri",
     re.compile(r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqps?)://[^\s:/@]+:[^\s/@]{3,}@[^\s]+"),
     0.78, 0.96, True, "Database URI with embedded password"),
    ("secret-slack-token",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
     0.75, 0.96, True, "Slack token"),
    ("secret-sendgrid-key",
     re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
     0.75, 0.96, True, "SendGrid API key"),
    ("secret-url-credentials",
     re.compile(r"\bhttps?://[^\s:/@]+:[^\s/@]{3,}@[^\s]+"),
     0.55, 0.90, False, "URL with embedded password"),
    ("secret-google-api-key",
     re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
     0.45, 0.85, False, "Google API key"),
    ("secret-jwt",
     re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
     0.45, 0.80, False, "JSON Web Token"),
    ("secret-test-key",
     re.compile(r"\b[rs]k_test_[A-Za-z0-9]{16,}\b"),
     0.15, 0.9, False, "Stripe TEST key (not a live credential)"),
    ("secret-openai-key",
     re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{10,}\b"),
     0.78, 0.95, True, "OpenAI API key"),
    ("secret-anthropic-key",
     re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
     0.78, 0.95, True, "Anthropic API key"),
    ("secret-npm-token",
     re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
     0.75, 0.95, True, "npm access token"),
    ("secret-twilio-key",
     re.compile(r"\bSK[0-9a-f]{32}\b"),
     0.70, 0.92, True, "Twilio API key"),
    ("secret-slack-webhook",
     re.compile(r"\bhttps://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}\b"),
     0.60, 0.95, True, "Slack incoming-webhook URL"),
]

_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_-]?key|api[_-]?secret|client[_-]?secret|secret|token|password|passwd|auth[_-]?token|private[_-]?key)"
    r"\s*[=:]\s*[\"']?([^\s\"',;]{10,200})")
_PLACEHOLDERS = ("xxx", "your-", "your_", "example", "changeme", "change-me", "placeholder",
                 "<", "todo", "none", "null", "true", "false", "redacted", "***")
_CARD = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
_SEED_LABEL = re.compile(r"(?i)\b(seed phrase|mnemonic|recovery phrase|secret recovery)\b")
_STRONG_CODES = {"secret-private-key", "secret-aws-key", "secret-github-token",
                 "secret-stripe-key", "secret-db-uri", "secret-slack-token",
                 "secret-sendgrid-key", "secret-openai-key", "secret-anthropic-key",
                 "secret-npm-token", "secret-twilio-key", "secret-slack-webhook"}


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {c: text.count(c) / len(text) for c in set(text)}
    return -sum(p * math.log2(p) for p in freq.values())


def _mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return "••••"
    return f"{value[:4]}…{value[-2:]}"


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return total % 10 == 0


def quick_detect(text: str) -> bool:
    """Cheap strong-format check used by Smart Scan routing: does this
    blob contain a recognisable credential format at all?"""
    return any(code in _STRONG_CODES and pattern.search(text)
               for code, pattern, *_ in _PATTERNS)


def scan_secrets(text: str) -> dict:
    """Scan pasted text for exposed credentials. The input is analysed
    in memory only; the output contains masked forms exclusively."""
    import time
    started = time.perf_counter()
    text = (text or "")[:100_000]
    findings: list[dict] = []
    signals: list[dict] = []
    spans: list[tuple[int, int]] = []
    seen: set[tuple[str, str]] = set()

    def record(code: str, raw: str, weight: float, confidence: float,
               deterministic: bool, label: str, span: tuple[int, int]) -> None:
        masked = _mask(raw)
        if (code, masked) in seen:
            return
        seen.add((code, masked))
        spans.append(span)
        points = int(round(100 * weight * confidence))
        findings.append({
            "points": points, "code": code,
            "message": f"{label} exposed: {masked} — treat it as compromised the moment it was pasted anywhere shared.",
            "fix": fix_for(code),
        })
        signals.append({
            "category": "secret_exposure", "weight": weight,
            "confidence": confidence, "deterministic": deterministic,
            "severity": "critical" if points >= 35 else "high" if points >= 20 else "medium",
        })

    for code, pattern, weight, confidence, deterministic, label in _PATTERNS:
        for m in pattern.finditer(text):
            record(code, m.group(0), weight, confidence, deterministic, label, m.span())

    # Generic KEY = value assignments with genuinely high-entropy
    # values, skipping spans already claimed by a specific pattern and
    # skipping obvious placeholders.
    for m in _ASSIGNMENT.finditer(text):
        value = m.group(2)
        if any(m.start(2) < end and start < m.end(2) for start, end in spans):
            continue
        lowered = value.lower()
        if any(p in lowered for p in _PLACEHOLDERS) or len(set(value)) < 6:
            continue
        if _entropy(value) < 3.4:
            continue
        record("secret-generic", value, 0.40, 0.60, False,
               f"High-entropy value assigned to '{m.group(1)}'", m.span(2))

    for m in _CARD.finditer(text):
        digits = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            record("secret-card-number", m.group(0), 0.55, 0.85, False,
                   "Payment-card number (Luhn-valid)", m.span())

    if _SEED_LABEL.search(text):
        record("secret-seed-phrase", "seed phrase", 0.70, 0.80, False,
               "Crypto wallet seed/recovery phrase", (0, 0))

    score = score_signals(signals)
    verdict = ("malicious" if score >= 70 else "suspicious" if score >= 40
               else "low-risk" if score > 0 else "clean")
    if not findings:
        findings.append({
            "points": 0, "code": "clean",
            "message": "No recognisable credentials found in this text.",
            "fix": fix_for("clean"),
        })
    result = {
        "risk_score": score, "verdict": verdict, "findings": findings,
        "secrets_found": len(seen),
        "types": sorted({code.removeprefix("secret-") for code, _ in seen}),
        "redacted": True,
    }
    return enrich(result, "secret-scan",
                  duration_ms=int((time.perf_counter() - started) * 1000))
