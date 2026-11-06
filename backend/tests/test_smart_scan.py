"""Smart Scan: classification, email splitting, dispatch and endpoint.

The classifier is pure and deterministic, so it is tested directly.
Dispatch is tested with the engines monkeypatched out (no network, no
heuristics drift); the endpoint is tested end-to-end with inputs whose
engines run fully offline.
"""

import pytest

from app.modules import smart_scan

# ── classify_input ───────────────────────────────────────────────────

@pytest.mark.parametrize("text", [
    "https://example.com/login",
    "http://192.168.1.9/paypal/login",
    "example.com/secure/verify",
    "bit.ly/3xYz9Ab",
    "www.bank-secure-login.xyz",
])
def test_classifies_links(text):
    assert smart_scan.classify_input(text) == "url"


@pytest.mark.parametrize("text", [
    "From: PayPal <service@paypa1.com>\nSubject: Verify your account\n\nDear customer, verify now.",
    "From: a@b.com\nTo: c@d.com\nSubject: hi\nDate: Mon, 1 Jan 2026 10:00:00 +0000\n\nBody text here.",
    "Subject: Invoice attached\nFrom: billing@example.com\n\nPlease pay the attached invoice.",
    # Lone leading From: line (other headers trimmed by the forwarder)
    "From: support@example.com\nYour OTP is 123456. Do not share it.",
])
def test_classifies_emails(text):
    assert smart_scan.classify_input(text) == "email"


@pytest.mark.parametrize("text", [
    "Your bank account will be blocked today. Update KYC immediately!",
    "Congratulations! You won a lottery. Click https://bit.ly/win to claim.",  # link inside a sentence stays a message
    "Dear sir, your parcel is held at customs. Pay 250 rupees to release it.",
    "someone@example.com",  # a bare address is not a link or an email
    "Subject: your parcel",  # a single line quoting a subject is a message, not an email
])
def test_classifies_messages(text):
    assert smart_scan.classify_input(text) == "message"


# ── split_email ──────────────────────────────────────────────────────

def test_split_email_headers_and_body():
    headers, body = smart_scan.split_email(
        "From: a@b.com\nSubject: Hi there\n\nFirst body line.\nSecond line."
    )
    assert headers == "From: a@b.com\nSubject: Hi there"
    assert body == "First body line.\nSecond line."


def test_split_email_no_headers():
    headers, body = smart_scan.split_email("Just a plain message body.")
    assert headers == ""
    assert body == "Just a plain message body."


def test_split_email_folded_header_line():
    headers, body = smart_scan.split_email(
        "Received: from mail.example.com\n\tby mx.example.com with ESMTP\nSubject: x\n\nBody."
    )
    assert "by mx.example.com" in headers
    assert body == "Body."


# ── dispatch (engines stubbed) ───────────────────────────────────────

class _FakeReport:
    def as_dict(self):
        return {"verdict": "malicious", "risk_score": 90, "findings": []}


def test_dispatch_url(monkeypatch):
    seen = {}

    def fake_analyze(url):
        seen["url"] = url
        return _FakeReport()

    monkeypatch.setattr(smart_scan.url_analyzer, "analyze_url", fake_analyze)
    out = smart_scan.smart_scan("https://example.com/login")
    assert seen["url"] == "https://example.com/login"
    assert out["detected_type"] == "url"
    assert out["tool"] == "Link Checker"
    assert out["verdict"] == "malicious"
    assert out["risk_score"] == 90
    assert out["result"]["risk_score"] == 90


def test_dispatch_email(monkeypatch):
    seen = {}

    def fake_analyze(headers, body):
        seen["headers"] = headers
        seen["body"] = body
        return {"verdict": "suspicious", "risk_score": 55, "findings": [], "from_domain": "b.com"}

    monkeypatch.setattr(smart_scan.email_analyzer, "analyze_email", fake_analyze)
    out = smart_scan.smart_scan("From: a@b.com\nSubject: hi\n\nBody text.")
    assert seen["headers"] == "From: a@b.com\nSubject: hi"
    assert seen["body"] == "Body text."
    assert out["detected_type"] == "email"
    assert out["tool"] == "Email Analyser"


def test_dispatch_message(monkeypatch):
    def fake_analyze(text):
        return {"verdict": "safe", "risk_score": 0, "findings": [], "links_found": []}

    monkeypatch.setattr(smart_scan.message_analyzer, "analyze_message", fake_analyze)
    out = smart_scan.smart_scan("hello, is this the bank?")
    assert out["detected_type"] == "message"
    assert out["tool"] == "Message Checker"
    assert out["verdict"] == "safe"


# ── endpoint ─────────────────────────────────────────────────────────

def test_endpoint_detects_link(client):
    r = client.post("/api/tools/smart-scan", json={"text": "http://192.168.1.9/paypal/login"})
    assert r.status_code == 200
    data = r.json()
    assert data["detected_type"] == "url"
    assert data["risk_score"] >= 50
    assert data["result"]["verdict"] == data["verdict"]


def test_endpoint_detects_message(client):
    r = client.post(
        "/api/tools/smart-scan",
        json={"text": "Your bank account will be blocked today. Update your KYC immediately to avoid closure!"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["detected_type"] == "message"
    assert "findings" in data["result"]


def test_endpoint_detects_email(client):
    r = client.post(
        "/api/tools/smart-scan",
        json={"text": "From: PayPal <service@paypa1-secure.com>\nSubject: Urgent: verify your account\n\nDear customer, your account is limited. Verify your password immediately."},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["detected_type"] == "email"
    assert data["risk_score"] > 0


def test_endpoint_rejects_blank(client):
    r = client.post("/api/tools/smart-scan", json={"text": "   "})
    assert r.status_code == 400


def test_endpoint_rejects_too_short(client):
    r = client.post("/api/tools/smart-scan", json={"text": "hi"})
    assert r.status_code == 422
