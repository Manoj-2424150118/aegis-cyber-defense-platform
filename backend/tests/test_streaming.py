"""Streaming (live agent view) tests: event order, step integrity, and
parity between streamed results and the classic JSON endpoints."""

import io
import json
import zipfile

PHISH_URL = "http://192.168.10.5/paypal/login/verify"

PHISH_HEADERS = (
    'From: "PayPal Support" <support@paypa1-secure.xyz>\n'
    "Reply-To: help@totally-different.ru\n"
    "Authentication-Results: mx.example.com; spf=fail dkim=fail dmarc=fail"
)
PHISH_BODY = "Urgent! Your account will be closed. Confirm your password and enter your OTP."


def _events(response) -> list[dict]:
    out = []
    for chunk in response.text.split("\n\n"):
        line = chunk.strip()
        if line.startswith("data: "):
            out.append(json.loads(line[6:]))
    return out


def test_url_stream_order_and_parity(client):
    classic = client.post("/api/tools/url", json={"url": PHISH_URL}).json()
    r = client.post("/api/tools/url/stream", json={"url": PHISH_URL})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    events = _events(r)
    assert events[0]["type"] == "start"
    steps = [e for e in events if e["type"] == "step"]
    assert [s["index"] for s in steps] == [1, 2, 3, 4, 5]
    assert events[-1]["type"] == "result"
    result = events[-1]["result"]
    assert result["risk_score"] == classic["risk_score"] == 85
    assert result["verdict"] == classic["verdict"]
    # every classic finding is accounted for across the streamed steps
    streamed_codes = sorted(f["code"] for s in steps for f in s["findings"])
    assert streamed_codes == sorted(f["code"] for f in classic["findings"])


def test_email_stream_parity(client):
    payload = {"headers": PHISH_HEADERS, "body": PHISH_BODY}
    classic = client.post("/api/tools/email", json=payload).json()
    events = _events(client.post("/api/tools/email/stream", json=payload))
    steps = [e for e in events if e["type"] == "step"]
    assert len(steps) == 4
    assert events[-1]["result"]["risk_score"] == classic["risk_score"]
    assert events[-1]["result"]["verdict"] == classic["verdict"]


def test_file_stream_parity(client):
    data = b"MZ" + b"\x00" * 512
    classic = client.post("/api/tools/file", files={"file": ("invoice.pdf", data)}).json()
    events = _events(client.post("/api/tools/file/stream", files={"file": ("invoice.pdf", data)}))
    steps = [e for e in events if e["type"] == "step"]
    assert len(steps) == 5
    result = events[-1]["result"]
    assert result["risk_score"] == classic["risk_score"]
    assert result["sha256"] == classic["sha256"]


def test_password_stream_shape(client):
    events = _events(client.post("/api/tools/password/stream", json={"password": "password123"}))
    steps = [e for e in events if e["type"] == "step"]
    assert len(steps) == 2
    assert steps[0]["detail"]["strength"] in ("very weak", "weak", "fair", "strong", "excellent")
    result = events[-1]["result"]
    assert "breach" in result and "source" in result["breach"]
    assert result["label"] == steps[0]["detail"]["strength"]


def test_web_audit_stream_blocks_ssrf(client):
    events = _events(client.post("/api/tools/web-audit/stream", json={"url": "http://169.254.169.254/latest/meta-data/"}))
    types = [e["type"] for e in events]
    assert "error" in types
    assert "result" not in types


def test_stream_zip_bomb_parity(client):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.bin", b"\x00" * 2_000_000)
    payload = buf.getvalue()
    classic = client.post("/api/tools/file", files={"file": ("a.zip", payload)}).json()
    events = _events(client.post("/api/tools/file/stream", files={"file": ("a.zip", payload)}))
    assert events[-1]["result"]["risk_score"] == classic["risk_score"]
    assert any(f["code"] == "zip-bomb" for s in events if s["type"] == "step" for f in s["findings"])
