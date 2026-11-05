"""Security regression tests — every loophole found in review gets a test
that must keep passing forever. See docs/QA_REPORT.md for the full battery."""

import io
import socket
import zipfile
from datetime import timedelta

import pytest

from app.modules.web_audit import UnsafeUrlError, assert_public_host, audit_website
from app.security import create_token

USER_A = {"email": "alice@example.com", "password": "StrongPass!2026-secure"}
USER_B = {"email": "bob@example.com", "password": "AnotherStrong!2026-pass"}


def _auth(client, creds):
    r = client.post("/api/auth/register", json=creds)
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# --- SSRF -----------------------------------------------------------------

@pytest.mark.parametrize("url", ["http://127.0.0.1/admin", "http://169.254.169.254/latest/meta-data/", "http://localhost:8000/", "http://[::1]/"])
def test_ssrf_targets_blocked(url):
    with pytest.raises(UnsafeUrlError):
        audit_website(url)


def test_ssrf_endpoint_returns_400_not_500(client):
    r = client.post("/api/tools/web-audit", json={"url": "http://169.254.169.254/latest/meta-data/"})
    assert r.status_code == 400


def test_ssrf_hostname_resolving_to_private_ip_blocked(monkeypatch):
    def fake_info(host, *a, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_info)
    with pytest.raises(UnsafeUrlError):
        assert_public_host("evil-internal.example.com")


def test_public_hostname_allowed(monkeypatch):
    def fake_info(host, *a, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_info)
    assert_public_host("example.com")  # must not raise


def test_non_http_scheme_rejected(client):
    r = client.post("/api/tools/web-audit", json={"url": "ftp://example.com/file"})
    assert r.status_code == 400


# --- Upload abuse -----------------------------------------------------------

def test_oversized_upload_rejected_413(client):
    big = b"A" * (10 * 1024 * 1024 + 1024)
    r = client.post("/api/tools/file", files={"file": ("big.bin", big, "application/octet-stream")})
    assert r.status_code == 413


def test_zip_with_excessive_entries_flagged():
    from app.modules.file_scanner import scan_file

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(1100):
            zf.writestr(f"f{i}.txt", "x")
    r = scan_file("many.zip", buf.getvalue())
    assert any(f["code"] == "excessive-entries" for f in r["findings"])


# --- Authorisation / IDOR ---------------------------------------------------

def test_vault_item_inaccessible_to_other_user(client):
    auth_a = _auth(client, USER_A)
    created = client.post(
        "/api/vault",
        json={"title": "A secret", "secret": "alice-only", "master_password": "MasterPass!2026-ok"},
        headers=auth_a,
    )
    item_id = created.json()["id"]
    auth_b = _auth(client, USER_B)
    r = client.post(f"/api/vault/{item_id}/open", json={"master_password": "MasterPass!2026-ok"}, headers=auth_b)
    assert r.status_code == 404  # not 403: existence itself is not leaked
    assert client.get("/api/vault", headers=auth_b).json() == []


def test_tampered_jwt_rejected(client):
    auth = _auth(client, USER_A)
    token = auth["Authorization"].split()[1]
    tampered = token[:-3] + ("aaa" if not token.endswith("aaa") else "bbb")
    r = client.get("/api/vault", headers={"Authorization": f"Bearer {tampered}"})
    assert r.status_code == 401


def test_expired_token_rejected(client):
    _auth(client, USER_A)
    expired = create_token(USER_A["email"], "access", timedelta(minutes=-1))
    r = client.get("/api/vault", headers={"Authorization": f"Bearer {expired}"})
    assert r.status_code == 401


def test_refresh_token_cannot_be_used_as_access(client):
    r = client.post("/api/auth/register", json=USER_A)
    refresh = r.json()["refresh_token"]
    res = client.get("/api/vault", headers={"Authorization": f"Bearer {refresh}"})
    assert res.status_code == 401


# --- Injection / XSS --------------------------------------------------------

def test_sql_injection_login_attempt_fails_safely(client):
    _auth(client, USER_A)
    r = client.post("/api/auth/login", json={"email": USER_A["email"], "password": "' OR '1'='1' --"})
    assert r.status_code == 401


def test_xss_payload_in_vault_title_stays_inert(client):
    auth = _auth(client, USER_A)
    payload = "<script>alert(document.cookie)</script>"
    r = client.post(
        "/api/vault",
        json={"title": payload, "secret": "s", "master_password": "MasterPass!2026-ok"},
        headers=auth,
    )
    assert r.status_code == 201
    assert r.headers["content-type"].startswith("application/json")
    listed = client.get("/api/vault", headers=auth)
    assert listed.headers["content-type"].startswith("application/json")


# --- Password policy ---------------------------------------------------------

def test_repetitive_password_registration_rejected(client):
    r = client.post("/api/auth/register", json={"email": "weak@example.com", "password": "aaaaaaaaaaaa"})
    assert r.status_code == 400


def test_unknown_user_login_is_generic_401(client):
    r = client.post("/api/auth/login", json={"email": "ghost@example.com", "password": "Whatever!2026-pass"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid email or password."


@pytest.mark.parametrize("payload", ["javascript:alert(1)", "data:text/html,<script>", "http://host:alert(1)/x", "http://a:b:c"])
def test_malformed_urls_never_500(client, payload):
    r = client.post("/api/tools/url", json={"url": payload})
    assert r.status_code == 200
    assert "risk_score" in r.json()


# --- Headers / rate limiting --------------------------------------------------

def test_hardening_headers_present(client):
    r = client.get("/health")
    assert r.headers["cross-origin-opener-policy"] == "same-origin"
    assert r.headers["cross-origin-resource-policy"] == "same-origin"
    assert r.headers["x-permitted-cross-domain-policies"] == "none"
    assert "x-request-id" in r.headers


def test_auth_rate_limit_kicks_in(client):
    codes = [
        client.post("/api/auth/login", json={"email": "nobody@example.com", "password": "x"}).status_code
        for _ in range(12)
    ]
    assert 429 in codes
