import pytest

from app.modules import vault
from app.modules.email_analyzer import analyze_email
from app.modules.web_audit import audit_headers

PHISH_HEADERS = """From: "PayPal Support" <support@paypa1-secure.xyz>
Reply-To: help@totally-different.ru
Return-Path: <bounce@mailer-other.net>
Authentication-Results: mx.example.com; spf=fail dkim=fail dmarc=fail
"""
PHISH_BODY = "Urgent! Your account will be closed within 24 hours. Confirm your password and enter your OTP immediately."


def test_phishing_email_scores_high():
    r = analyze_email(PHISH_HEADERS, PHISH_BODY)
    assert r["risk_score"] >= 60
    codes = {f["code"] for f in r["findings"]}
    assert "spf-fail" in codes and "reply-to-mismatch" in codes


def test_benign_email_scores_low():
    headers = """From: Priya <priya@company.com>
Authentication-Results: mx; spf=pass dkim=pass dmarc=pass
"""
    r = analyze_email(headers, "Hi, sharing the meeting notes from Tuesday. Regards")
    assert r["risk_score"] < 30


def test_vault_roundtrip():
    blob = vault.encrypt_item("correct horse battery staple", vault.new_salt(), "my bank PIN is 4321")
    assert "4321" not in blob
    assert vault.decrypt_item("correct horse battery staple", blob) == "my bank PIN is 4321"


def test_vault_wrong_password_fails():
    blob = vault.encrypt_item("right-password-123", vault.new_salt(), "secret")
    with pytest.raises(ValueError):
        vault.decrypt_item("wrong-password-456", blob)


def test_vault_tampering_detected():
    blob = vault.encrypt_item("right-password-123", vault.new_salt(), "secret")
    raw = bytearray(__import__("base64").urlsafe_b64decode(blob))
    raw[-1] ^= 1
    tampered = __import__("base64").urlsafe_b64encode(bytes(raw)).decode()
    with pytest.raises(ValueError):
        vault.decrypt_item("right-password-123", tampered)


def test_web_audit_good_site():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=()",
    }
    r = audit_headers("https://example.com", headers, ["sid=1; Secure; HttpOnly; SameSite=Lax"], https=True)
    assert r["grade"] in ("A", "B")
    assert r["score"] >= 85


def test_web_audit_bad_site():
    r = audit_headers("http://example.com", {}, [], https=False)
    assert r["grade"] == "F"
