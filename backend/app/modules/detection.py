"""Shared detection core — the Signal layer every engine reports through.

The engines keep their own calibrated, unit-tested scorers (additive
points, pinned by the golden corpus). This module is the *reporting*
layer the detection-upgrade spec adds on top of them:

* every finding becomes a typed :class:`Signal` view with a category,
  severity, confidence and a mandatory prevention action — the UI and
  API consumers get evidence, not just a number;
* every result gains a one-sentence ``summary``, an ordered
  ``prevention`` playbook, an overall ``confidence`` and a ``meta``
  block (schema version, duration, sources, degraded flag);
* new engines (the secret scanner) score *natively* in this model via
  :func:`score_signals` — noisy-OR combination of independent evidence
  with per-category caps and deterministic hard rules.

Backward compatibility is absolute: ``findings`` / ``risk_score`` /
``verdict`` / ``grade`` are never altered by enrichment.
"""

from __future__ import annotations

import math

SCHEMA_VERSION = "2.0"

# ── Categories ───────────────────────────────────────────────────────
# Finding code → signal category. Prefix rules cover parameterised
# codes (missing-*, spf-*, tls-*…). Anything unmapped is "general".
_CATEGORY_BY_CODE = {
    # brand impersonation
    "brand-in-host": "brand_impersonation", "brand-in-path": "brand_impersonation",
    "typosquat": "brand_impersonation", "punycode": "brand_impersonation",
    "unicode-host": "brand_impersonation", "mixed-script-host": "brand_impersonation",
    "homograph-host": "brand_impersonation",
    "homograph-domain": "brand_impersonation", "display-name-spoof": "brand_impersonation",
    "freemail-impersonation": "brand_impersonation", "free-host-abuse": "brand_impersonation",
    # host / network structure
    "ip-host": "host_structure", "obfuscated-ip": "host_structure",
    "many-subdomains": "host_structure", "high-entropy-host": "host_structure",
    "unparseable": "host_structure", "malformed-port": "host_structure",
    "odd-port": "host_structure", "userinfo-trick": "host_structure",
    "embedded-credentials": "host_structure", "suspicious-tld": "host_structure",
    # transport
    "no-https": "transport", "dangerous-scheme": "transport",
    # lexical / content lure
    "phish-keywords": "lexical", "very-long": "lexical", "encoded-path": "lexical",
    "hyphen-stuffing": "lexical", "double-slash": "lexical",
    "shortener": "lexical", "redirect-param": "lexical",
    "wrapped-destination": "lexical",
    # payload delivery
    "executable-download": "payload", "archive-download": "payload",
    # tracking / privacy
    "tracking-params": "tracking", "tracking-wrapper": "tracking",
    "tracking-pixel": "tracking",
    # sender authentication & consistency
    "reply-to-mismatch": "sender_consistency", "return-path-mismatch": "sender_consistency",
    "messageid-mismatch": "sender_consistency", "received-private-hop": "sender_consistency",
    # social engineering
    "urgency-pressure": "social_engineering", "urgency-language": "social_engineering",
    "credential-bait": "social_engineering", "credential-form": "social_engineering",
    "giftcard-scam": "social_engineering", "bec-wire": "social_engineering",
    "bec-payroll": "social_engineering",
    "malicious-link": "social_engineering", "suspicious-link": "social_engineering",
    "link-text-mismatch": "social_engineering", "hidden-text": "social_engineering",
    "link-present": "social_engineering", "upi-payment-ask": "social_engineering",
    "kyc-threat": "social_engineering", "digital-arrest": "social_engineering",
    "prize-scam": "social_engineering", "task-scam": "social_engineering",
    "crypto-doubling": "social_engineering", "investment-scam": "social_engineering",
    "sextortion": "social_engineering", "tax-refund-scam": "social_engineering",
    "forwarded-chain": "social_engineering",
    "parcel-scam": "social_engineering", "family-emergency": "social_engineering",
    "tech-support-scam": "social_engineering", "loan-scam": "social_engineering",
    "callback-number": "social_engineering",
    # file / malware
    "type-spoofing": "malware", "double-extension": "malware",
    "dangerous-type": "malware", "high-entropy": "malware",
    "macros-present": "malware", "remote-template": "malware",
    "pdf-active-content": "malware", "zip-bomb": "malware", "lnk-suspicious-target": "malware",
    "html-smuggling": "malware",
    "excessive-entries": "malware", "archive-hides-executable": "malware",
    "archive-traversal": "malware", "nested-archive": "malware",
    "encrypted-archive": "malware", "corrupt-archive": "malware",
    "eicar-test": "malware",
    # posture (domain / tls / web-audit — informational polarity)
    "clean": "general",
}

_CATEGORY_PREFIXES = (
    ("spf-", "sender_authentication"), ("dkim-", "sender_authentication"),
    ("dmarc-", "sender_authentication"),
    ("tls-", "transport"), ("missing-", "posture"), ("dns-", "posture"),
    ("mx-", "posture"), ("caa-", "posture"), ("dkim", "posture"),
    ("embedded-", "malware"), ("powershell-", "malware"),
    ("certutil-", "malware"), ("shell-", "malware"), ("base64-", "malware"),
    ("crypto-", "malware"), ("mshta-", "malware"), ("rundll32-", "malware"),
    ("amsi-", "malware"), ("credential-theft", "malware"),
    ("exec-policy-", "malware"), ("hidden-window", "malware"),
    ("macro-", "malware"), ("secret-", "secret_exposure"),
)

# Codes whose presence is a fact, not a suspicion — they raise the
# result's confidence because the evidence is deterministic.
DETERMINISTIC_CODES = {
    "eicar-test", "dangerous-scheme", "ip-host", "obfuscated-ip",
    "embedded-credentials", "type-spoofing", "double-extension",
    "spf-fail", "dkim-fail", "dmarc-fail", "zip-bomb",
    "secret-private-key", "secret-aws-key", "secret-github-token",
    "secret-stripe-key", "secret-slack-token", "secret-db-uri",
}

# Per-category caps for the noisy-OR scorer (max combined weight a
# single theme may contribute) — one theme must not stack to 100.
CATEGORY_CAPS = {
    "lexical": 0.30, "tracking": 0.15, "social_engineering": 0.85,
    "brand_impersonation": 0.90, "host_structure": 0.90,
    "malware": 0.98, "secret_exposure": 0.98,
}
_DEFAULT_CAP = 0.95


def category_for(code: str) -> str:
    if code in _CATEGORY_BY_CODE:
        return _CATEGORY_BY_CODE[code]
    for prefix, category in _CATEGORY_PREFIXES:
        if code.startswith(prefix):
            return category
    return "general"


def severity_for(points: int) -> str:
    if points <= 0:
        return "info"
    if points < 10:
        return "low"
    if points < 20:
        return "medium"
    if points < 35:
        return "high"
    return "critical"


def _title_for(code: str) -> str:
    return code.replace("-", " ").strip().capitalize()


def signal_from_finding(finding: dict, engine: str) -> dict:
    """Typed Signal view of one legacy finding (additive, non-destructive)."""
    code = finding.get("code", "general")
    points = int(finding.get("points", 0))
    deterministic = code in DETERMINISTIC_CODES
    # Deterministic evidence is near-certain; heuristic keyword-style
    # evidence is stated with honest, lower confidence.
    confidence = 0.95 if deterministic else 0.55 + min(0.35, points / 60.0) if points else 0.5
    fix = finding.get("fix", "")
    return {
        "id": f"{engine}.{code}",
        "engine": engine,
        "category": category_for(code),
        "severity": severity_for(points),
        "confidence": round(confidence, 2),
        "points": points,
        "deterministic": deterministic,
        "title": _title_for(code),
        "explain": finding.get("message", ""),
        "prevention": {"immediate": fix} if fix else {},
    }


def verdict_band(score: int) -> str:
    """The five-band verdict scale from the spec (an added field — the
    legacy three/four-value ``verdict`` is unchanged for compatibility)."""
    if score >= 80:
        return "malicious"
    if score >= 60:
        return "suspicious"
    if score >= 40:
        return "caution"
    if score >= 15:
        return "likely_safe"
    return "safe"


def confidence_for(findings: list[dict], score: int) -> float:
    """Overall result confidence, kept separate from severity: it says
    how much evidence backs the verdict, not how bad the verdict is."""
    active = [f for f in findings if int(f.get("points", 0)) > 0]
    if not active:
        # A clean result is an absence of evidence, stated honestly.
        return 0.55
    categories = {category_for(f.get("code", "")) for f in active}
    value = 0.45 + 0.12 * len(categories) + min(0.15, score / 600.0)
    if any(f.get("code") in DETERMINISTIC_CODES for f in active):
        value += 0.20
    return round(max(0.05, min(0.98, value)), 2)


def summary_for(engine: str, verdict: str, score: int, findings: list[dict]) -> str:
    active = [f for f in findings if int(f.get("points", 0)) > 0]
    if not active:
        return "No threat signals detected by the checks that ran."
    top = max(active, key=lambda f: int(f.get("points", 0)))
    return f"{verdict.replace('-', ' ').capitalize()} ({score}/100) — {top.get('message', '')}"


def prevention_playbook(findings: list[dict], limit: int = 3) -> list[dict]:
    """Ordered, concrete actions: the fixes of the strongest findings,
    strongest first. A clean result still yields its standing advice."""
    ranked = sorted(findings, key=lambda f: -int(f.get("points", 0)))
    playbook: list[dict] = []
    seen: set[str] = set()
    for f in ranked:
        fix = (f.get("fix") or "").strip()
        if not fix or fix in seen:
            continue
        seen.add(fix)
        playbook.append({
            "priority": len(playbook) + 1,
            "action": fix,
            "why": f.get("message", ""),
        })
        if len(playbook) >= limit:
            break
    return playbook


def enrich(result: dict, engine: str, *, duration_ms: int = 0,
           sources_used: tuple[str, ...] = (), degraded: bool = False) -> dict:
    """Return a copy of an engine result with the v2 reporting layer:
    ``signals``, ``summary``, ``prevention``, ``confidence``,
    ``verdict_band`` and ``meta``. Legacy keys pass through untouched."""
    findings = result.get("findings", [])
    score = int(result.get("risk_score", result.get("score", 0)))
    enriched = dict(result)
    enriched["signals"] = [signal_from_finding(f, engine) for f in findings]
    enriched["summary"] = summary_for(engine, str(result.get("verdict", "")), score, findings)
    enriched["prevention"] = prevention_playbook(findings)
    enriched["confidence"] = confidence_for(findings, score)
    enriched["verdict_band"] = verdict_band(score)
    enriched["meta"] = {
        "schema_version": SCHEMA_VERSION,
        "engine": engine,
        "duration_ms": duration_ms,
        "sources_used": list(sources_used),
        "degraded": degraded,
        "cached": False,
    }
    return enriched


def score_signals(signals: list[dict]) -> int:
    """Noisy-OR scoring for engines built natively on Signals.

    Each signal contributes ``weight × confidence``; independent
    evidence combines as ``1 − Π(1 − w·c)`` per category, categories
    are capped (one theme cannot stack to 100), then combined again.
    A deterministic critical signal is a hard rule: the score floors
    at 90 regardless of the arithmetic.
    """
    by_category: dict[str, list[float]] = {}
    hard_floor = 0
    for s in signals:
        w = max(0.0, min(1.0, float(s.get("weight", s.get("points", 0) / 100.0))))
        c = max(0.0, min(1.0, float(s.get("confidence", 0.8))))
        by_category.setdefault(s.get("category", "general"), []).append(w * c)
        if s.get("deterministic") and s.get("severity") == "critical":
            hard_floor = max(hard_floor, 90)
    combined_categories: list[float] = []
    for category, parts in by_category.items():
        combined = 1.0 - math.prod(1.0 - p for p in parts)
        combined_categories.append(min(combined, CATEGORY_CAPS.get(category, _DEFAULT_CAP)))
    total = 1.0 - math.prod(1.0 - c for c in combined_categories) if combined_categories else 0.0
    return max(hard_floor, int(round(100 * total)))


def enrich_meta(result: dict, engine: str, *, duration_ms: int = 0,
                sources_used: tuple[str, ...] = (), degraded: bool = False) -> dict:
    """Light enrichment for the posture engines (domain / TLS / web
    audit), whose scores grade *good* controls rather than risk: they
    gain ``summary`` + ``meta`` without the risk-signal layer."""
    enriched = dict(result)
    label = str(result.get("verdict") or result.get("grade") or "")
    score = int(result.get("risk_score", result.get("score", 0)))
    enriched["summary"] = summary_for(engine, label, score, result.get("findings", []))
    enriched["meta"] = {
        "schema_version": SCHEMA_VERSION,
        "engine": engine,
        "duration_ms": duration_ms,
        "sources_used": list(sources_used),
        "degraded": degraded,
        "cached": False,
    }
    return enriched
