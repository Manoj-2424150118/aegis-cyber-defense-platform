"""Detection-engine upgrade (spec phases) — regression tests.

Grows phase by phase; every test names the spec section it pins.
"""
import io
import zipfile

from app.modules import enrichment
from app.modules.domain_checker import evaluate_domain
from app.modules.email_analyzer import analyze_email
from app.modules.file_scanner import scan_file
from app.modules.message_analyzer import analyze_message
from app.modules.secret_scanner import scan_secrets
from app.modules.url_analyzer import analyze_url


def _codes(result) -> set[str]:
    return {f["code"] for f in result["findings"]}


# ── Phase 1: enrichment source-access layer (spec §2/§6) ───────────

def test_ttl_cache_roundtrip_and_expiry():
    cache = enrichment.TTLCache(ttl_seconds=60)
    assert cache.get("k") is None
    cache.put("k", {"v": 1})
    assert cache.get("k") == {"v": 1}
    stale = enrichment.TTLCache(ttl_seconds=-1)
    stale.put("k", 1)
    assert stale.get("k") is None


def test_circuit_breaker_opens_and_recovers():
    breaker = enrichment.CircuitBreaker(failure_threshold=2, cooldown_seconds=0.0)
    assert breaker.allow()
    breaker.record_failure()
    breaker.record_failure()
    # Cooldown of 0 means the next trial call is allowed immediately,
    # and a success fully closes the breaker again.
    assert breaker.allow()
    breaker.record_success()
    assert breaker.allow()


def test_fetch_json_degrades_to_none_on_error():
    breaker = enrichment.CircuitBreaker(failure_threshold=1, cooldown_seconds=600)
    breaker.record_failure()
    # Open breaker: no network attempt is even made.
    assert enrichment.fetch_json("https://rdap.org/domain/example.com", breaker=breaker) is None


# ── Phase 1: prevention on 100% of findings (spec §7/§14) ──────────

def test_every_finding_carries_a_fix_across_engines():
    samples = [
        analyze_url("http://192.168.10.5/paypal/login/verify").as_dict(),
        analyze_url("https://example.com/").as_dict(),
        analyze_email("From: CEO <ceo@company.com>\nAuthentication-Results: mx; spf=fail\n",
                      "Urgent wire transfer, keep this confidential."),
        analyze_message("Your parcel is held — pay customs fee Rs 49: http://x.xyz"),
        analyze_message("hello there friend"),
        scan_secrets("token = <redacted>"),
        scan_file("invoice.pdf.exe", b"MZ" + b"\x00" * 64),
        evaluate_domain("example.com", {
            "a": [], "aaaa": [], "mx": [], "ns": [], "spf": [], "dmarc": [],
            "caa": [], "cname": [], "cname_resolves": True, "dkim": [], "rdap_created": None,
        }),
    ]
    for result in samples:
        for finding in result["findings"]:
            assert finding.get("fix"), f"finding {finding['code']} has no prevention/fix"
        for signal in result.get("signals", []):
            assert signal["prevention"], f"signal {signal['id']} has no prevention"


# ── Phase 2: URL evasion counters (spec §5.1/§8) ────────────────────

def test_url_tab_in_scheme_is_still_dangerous():
    r = analyze_url("java\tscript:alert(1)")
    assert "dangerous-scheme" in _codes(r.as_dict())


def test_url_pure_foreign_script_homograph_matches_brand_skeleton():
    # р, а, у are Cyrillic; the label renders as "paypal" but is not.
    r = analyze_url("http://раураl.com/login")
    codes = _codes(r.as_dict())
    assert "homograph-host" in codes
    assert r.risk_score >= 40


def test_url_real_brand_domain_not_flagged_as_homograph():
    r = analyze_url("https://www.paypal.com/signin")
    assert "homograph-host" not in _codes(r.as_dict())


# ── Phase 3: domain lookalikes + TLS notes (spec §5.6/§5.7) ────────

from app.modules.domain_checker import lookalike_permutations
from app.modules.tls_inspector import grade_certificate

_BASE = {
    "a": ["1.2.3.4"], "aaaa": [], "mx": ["10 mail.example.com"], "ns": ["ns1.example.com"],
    "spf": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=reject"], "caa": [],
    "cname": [], "cname_resolves": True, "dkim": [], "rdap_created": None,
}


def test_lookalike_permutations_are_bounded_and_exclude_original():
    perms = lookalike_permutations("paypal.com")
    assert "paypal.com" not in perms
    assert "paypa.com" in perms          # deletion
    assert "paypal.co" in perms          # TLD swap
    assert len(perms) <= 40


def test_resolving_lookalike_is_a_zero_point_note():
    base = evaluate_domain("example.com", dict(_BASE))
    noted = evaluate_domain("example.com", {**_BASE, "lookalikes_resolving": ["examp1e.com"]})
    assert noted["score"] == base["score"]
    assert "lookalike-resolving" in _codes(noted)


def test_tls_wildcard_and_newly_issued_are_zero_point_notes():
    cert = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Test CA"),),),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "*.example.com")),
        "notAfter": "Dec 31 23:59:59 2099 GMT",
        "notBefore": "Jan 1 00:00:00 2099 GMT",
    }
    from datetime import datetime, timezone
    plain = grade_certificate("example.com", {**cert, "subjectAltName": (("DNS", "example.com"),)}, "TLSv1.3", True, now=datetime(2099, 6, 1, tzinfo=timezone.utc))
    noted = grade_certificate("example.com", cert, "TLSv1.3", True, now=datetime(2099, 6, 1, tzinfo=timezone.utc))
    assert noted["score"] == plain["score"]
    assert "tls-wildcard" in _codes(noted)
    fresh = grade_certificate("example.com", cert, "TLSv1.3", True, now=datetime(2099, 1, 3, tzinfo=timezone.utc))
    assert "tls-newly-issued" in _codes(fresh)


# ── Phase 4: email Received-chain forensics (spec §5.4) ─────────────

def test_email_private_originating_hop_flagged():
    headers = (
        "From: Bank <alerts@bank.example.com>\n"
        "Authentication-Results: mx; spf=pass dkim=pass dmarc=pass\n"
        "Received: from mx.bank.example.com (mx.bank.example.com [93.184.216.34]) by mx.google.com\n"
        "Received: from laptop (unknown [192.168.1.45]) by mx.bank.example.com\n"
    )
    r = analyze_email(headers, "Your statement is ready.")
    assert "received-private-hop" in _codes(r)


def test_email_public_origin_not_flagged():
    headers = (
        "From: Bank <alerts@bank.example.com>\n"
        "Authentication-Results: mx; spf=pass dkim=pass dmarc=pass\n"
        "Received: from mx.bank.example.com (mx.bank.example.com [93.184.216.34]) by mx.google.com\n"
    )
    r = analyze_email(headers, "Your statement is ready.")
    assert "received-private-hop" not in _codes(r)


# ── Phase 5: message playbooks (spec §5.5) ──────────────────────────

def test_message_sextortion_and_tax_and_forwarded_playbooks():
    assert "sextortion" in _codes(analyze_message("I have recorded your webcam. Pay or I will share the video with your contacts."))
    assert "tax-refund-scam" in _codes(analyze_message("Your income tax refund is pending. Claim your refund here to receive it."))
    assert "forwarded-chain" in _codes(analyze_message("Forwarded many times: Good morning, share this with 10 friends"))


# ── Phase 6: password zxcvbn-style reporting (spec §5.2) ────────────

from app.modules.password_lab import assess_password


def test_password_strength_score_and_crack_times_present():
    weak = assess_password("password")
    assert weak["strength_score"] == 0
    strong = assess_password("Tr7!mango-BICYCLE-92#quartz")
    assert strong["strength_score"] >= 3
    assert strong["guesses_log10"] > weak["guesses_log10"]
    assert set(strong["crack_times"]) == {"online_throttled", "offline_fast_hash"}
    # Legacy contract untouched.
    assert strong["label"] in ("strong", "excellent") and "score" in strong


# ── Phase 7: file IOC values, LNK, HTML smuggling (spec §5.3) ──────

def test_file_ioc_values_extracted():
    payload = b"contact admin@evil.example.com or http://198.51.100.9:8080/drop and pay 0x" + b"a" * 40
    # use a genuinely public-looking IP for realism in the fixture
    payload = payload.replace(b"198.51.100.9", b"45.155.204.9")
    r = scan_file("notes.txt", payload)
    assert "45.155.204.9:8080" in r["iocs"]["ips"] or any("45.155.204.9" in v for v in r["iocs"]["ips"])
    assert any("evil.example.com" in e for e in r["iocs"]["emails"])
    assert r["external_engines"] == {"yara": "not-configured", "clamav": "not-configured"}


def test_file_lnk_with_shell_target_flagged():
    lnk = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46" + \
          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -enc aGVsbG8=".encode("utf-16-le")
    r = scan_file("invoice.lnk", lnk)
    assert "lnk-suspicious-target" in _codes(r)


def test_file_html_smuggling_flagged():
    html = b"<html><script>var b=atob('TVqQ...');var u=URL.createObjectURL(new Blob([b]));</script></html>"
    r = scan_file("report.html", html)
    assert "html-smuggling" in _codes(r)


# ── Phase 8: web-audit CSP strength + HSTS quality (spec §5.8) ─────

from app.modules.web_audit import audit_headers


def test_audit_weak_csp_flagged_without_score_change():
    strong = audit_headers("https://x.example", {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'; script-src 'self'",
        "x-content-type-options": "nosniff", "x-frame-options": "DENY",
        "referrer-policy": "no-referrer", "permissions-policy": "camera=()",
    }, [], https=True)
    weak = audit_headers("https://x.example", {
        "strict-transport-security": "max-age=300",
        "content-security-policy": "default-src *; script-src 'unsafe-inline' 'unsafe-eval' *",
        "x-content-type-options": "nosniff", "x-frame-options": "DENY",
        "referrer-policy": "no-referrer", "permissions-policy": "camera=()",
    }, [], https=True)
    codes = _codes(weak)
    assert {"csp-unsafe-inline", "csp-unsafe-eval", "csp-wildcard", "hsts-weak"} <= codes
    assert "csp-unsafe-inline" not in _codes(strong)
    assert weak["score"] == strong["score"]  # notes never move the posture score
