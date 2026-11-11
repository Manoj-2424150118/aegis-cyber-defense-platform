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
