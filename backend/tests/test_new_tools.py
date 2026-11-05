"""v1.6 tools: scam-message analyser, domain checker, TLS inspector.

Network engines are tested through their pure grading functions and
through the API with the fetch layer monkeypatched — the same split
the web audit uses (audit_headers vs _fetch_guarded).
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.modules import domain_checker, tls_inspector
from app.modules.message_analyzer import analyze_message, extract_links

SCAM = (
    "Dear customer, your bank account will be blocked today due to pending KYC. "
    "Verify immediately at http://secure-kyc-update.xyz/verify and share the OTP "
    "sent to your mobile to avoid suspension."
)
ARREST = "This is CBI cyber cell. A parcel with narcotics was booked in your name. You are under digital arrest. Pay the verification amount to the officer's UPI ID officer.pay@okhdfc to clear your case immediately."
BENIGN = "Hi, reminder that our book club meets on Saturday at 5pm at the library. Bring the novel we discussed!"


# ── Message analyser ─────────────────────────────────────────────────

def test_scam_message_scores_high():
    r = analyze_message(SCAM)
    codes = {f["code"] for f in r["findings"]}
    assert r["risk_score"] >= 60
    assert "credential-bait" in codes and "kyc-threat" in codes
    assert r["links_found"]
    assert all(f.get("fix") for f in r["findings"])


def test_digital_arrest_playbook_detected():
    r = analyze_message(ARREST)
    codes = {f["code"] for f in r["findings"]}
    assert "digital-arrest" in codes
    assert "upi-payment-ask" in codes
    assert r["risk_score"] >= 40


def test_task_scam_and_bare_telegram():
    r = analyze_message("Earn per day Rs 5000! Join our Telegram group, like and subscribe tasks, registration fee only Rs 500.")
    assert "task-scam" in {f["code"] for f in r["findings"]}
    r2 = analyze_message("Our class notes are shared on Telegram, check the channel when free.")
    assert "task-scam" not in {f["code"] for f in r2["findings"]}


def test_benign_message_is_safe():
    r = analyze_message(BENIGN)
    assert r["verdict"] == "safe"
    assert r["findings"][0]["code"] == "clean"


def test_extract_links_shapes():
    links = extract_links("go to https://a.example.com/x or www.b-site.org or plain c.xyz/page now")
    assert any("a.example.com" in link for link in links)
    assert any("b-site.org" in link for link in links)
    assert any("c.xyz" in link for link in links)


def test_message_endpoint_and_stream_parity(client):
    classic = client.post("/api/tools/message", json={"text": SCAM}).json()
    assert classic["risk_score"] >= 60
    r = client.post("/api/tools/message/stream", json={"text": SCAM})
    assert r.status_code == 200
    assert '"result"' in r.text.replace(" ", "") or "result" in r.text


def test_message_endpoint_rejects_blank(client):
    assert client.post("/api/tools/message", json={"text": "   "}).status_code == 400


# ── Domain checker ───────────────────────────────────────────────────

GOOD = {
    "a": ["93.184.216.34"], "aaaa": [], "mx": ["10 mail.example.com."], "ns": ["ns1.example.com."],
    "spf": ["v=spf1 include:_spf.example.com -all"],
    "dmarc": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
    "caa": ['0 issue "letsencrypt.org"'],
}
BAD = {"a": [], "aaaa": [], "mx": [], "ns": [], "spf": [], "dmarc": [], "caa": []}


def test_domain_good_scores_high():
    r = domain_checker.evaluate_domain("example.com", GOOD)
    assert r["score"] == 100 and r["grade"] == "A"
    assert all(f.get("fix") for f in r["findings"])


def test_domain_bad_scores_zero():
    r = domain_checker.evaluate_domain("example.com", BAD)
    assert r["score"] == 0 and r["grade"] == "F"
    codes = {f["code"] for f in r["findings"]}
    assert {"dns-dead", "mx-missing", "spf-missing", "dmarc-missing", "caa-missing"} <= codes


def test_domain_partial_policies():
    rec = dict(GOOD, spf=["v=spf1 ~all"], dmarc=["v=DMARC1; p=none"])
    r = domain_checker.evaluate_domain("example.com", rec)
    codes = {f["code"] for f in r["findings"]}
    assert "spf-soft" in codes and "dmarc-monitor" in codes
    rec2 = dict(GOOD, spf=["v=spf1 -all", "v=spf1 include:x -all"])
    assert "spf-multiple" in {f["code"] for f in domain_checker.evaluate_domain("example.com", rec2)["findings"]}


def test_domain_endpoint_uses_fetch_layer(client, monkeypatch):
    monkeypatch.setattr(domain_checker, "fetch_records", lambda d: GOOD)
    r = client.post("/api/tools/domain", json={"domain": "example.com"})
    assert r.status_code == 200 and r.json()["score"] == 100
    assert client.post("/api/tools/domain", json={"domain": "bad_host.example"}).status_code == 400


# ── TLS inspector ────────────────────────────────────────────────────

def _cert(days: int, san=("example.com",), cn="example.com"):
    expiry = datetime.now(timezone.utc) + timedelta(days=days)
    return {
        "subject": ((("commonName", cn),),),
        "issuer": ((("organizationName", "Let's Encrypt"),),),
        "subjectAltName": tuple(("DNS", d) for d in san),
        "notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT"),
    }


def test_tls_good_certificate():
    r = tls_inspector.grade_certificate("example.com", _cert(90), "TLSv1.3", True)
    assert r["score"] == 100 and r["grade"] == "A"
    assert r["facts"]["days_left"] >= 89
    assert all(f.get("fix") for f in r["findings"])


def test_tls_expired_and_mismatched():
    r = tls_inspector.grade_certificate("example.com", _cert(-5, san=("other.com",)), "TLSv1.0", False)
    codes = {f["code"] for f in r["findings"]}
    assert {"tls-expired", "tls-hostname-mismatch", "tls-weak-protocol", "tls-unverified"} <= codes
    assert r["score"] < 35


def test_tls_wildcard_match():
    r = tls_inspector.grade_certificate("app.example.com", _cert(60, san=("*.example.com",)), "TLSv1.2", True)
    assert "tls-hostname-match" in {f["code"] for f in r["findings"]}


def test_tls_endpoint_blocks_private_host(client):
    r = client.post("/api/tools/tls", json={"host": "http://169.254.169.254/"})
    assert r.status_code == 400


def test_tls_endpoint_validates_host(client):
    assert client.post("/api/tools/tls", json={"host": "bad_host!"}).status_code == 400


def test_new_tools_have_fixes_everywhere():
    for report in (
        analyze_message(SCAM),
        analyze_message(ARREST),
        domain_checker.evaluate_domain("example.com", GOOD),
        domain_checker.evaluate_domain("example.com", BAD),
        tls_inspector.grade_certificate("example.com", _cert(90), "TLSv1.3", True),
        tls_inspector.grade_certificate("example.com", _cert(-1), "TLSv1.0", False),
    ):
        for f in report["findings"]:
            assert f.get("fix") and len(f["fix"]) > 20, f


@pytest.mark.parametrize("payload", [{"domain": "exa mple.com"}, {"domain": "https://ok.example.com/path"}])
def test_domain_schema_whitespace_and_url_form(client, monkeypatch, payload):
    monkeypatch.setattr(domain_checker, "fetch_records", lambda d: GOOD)
    r = client.post("/api/tools/domain", json=payload)
    if " " in payload["domain"]:
        assert r.status_code == 422
    else:
        assert r.status_code == 200  # URL form is normalised to its host
