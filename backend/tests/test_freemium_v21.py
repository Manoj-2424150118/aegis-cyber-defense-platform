"""v2.1.0 — freemium quotas, vault cap, HIBP signup gate, TOTP MFA."""

import time

from app.config import settings
from app.modules import totp as totp_mod

CREDS = {"email": "tier@example.com", "password": "StrongPass!2026-secure"}
URL_BODY = {"url": "https://example.com"}


def _register(client, creds=CREDS):
    r = client.post("/api/auth/register", json=creds)
    assert r.status_code == 201, r.text
    return r.json()["access_token"]


# ------------------------------------------------------------------ quotas


def test_anonymous_quota_blocks_after_limit(client, monkeypatch):
    monkeypatch.setattr(settings, "anon_daily_scan_limit", 3)
    headers = {"CF-Connecting-IP": "203.0.113.10"}
    for _ in range(3):
        assert client.post("/api/tools/url", json=URL_BODY, headers=headers).status_code == 200
    r = client.post("/api/tools/url", json=URL_BODY, headers=headers)
    assert r.status_code == 429
    assert "free account" in r.json()["detail"]


def test_quota_is_per_caller_not_global(client, monkeypatch):
    monkeypatch.setattr(settings, "anon_daily_scan_limit", 1)
    a = {"CF-Connecting-IP": "203.0.113.20"}
    b = {"CF-Connecting-IP": "203.0.113.21"}
    assert client.post("/api/tools/url", json=URL_BODY, headers=a).status_code == 200
    assert client.post("/api/tools/url", json=URL_BODY, headers=a).status_code == 429
    assert client.post("/api/tools/url", json=URL_BODY, headers=b).status_code == 200


def test_account_token_uses_account_limit_and_its_own_pool(client, monkeypatch):
    monkeypatch.setattr(settings, "anon_daily_scan_limit", 1)
    monkeypatch.setattr(settings, "account_daily_scan_limit", 2)
    headers = {"CF-Connecting-IP": "203.0.113.30"}
    assert client.post("/api/tools/url", json=URL_BODY, headers=headers).status_code == 200
    assert client.post("/api/tools/url", json=URL_BODY, headers=headers).status_code == 429
    token = _register(client)
    auth = {**headers, "Authorization": f"Bearer {token}"}
    # The signed-in pool is separate from the anonymous IP pool.
    assert client.post("/api/tools/url", json=URL_BODY, headers=auth).status_code == 200
    assert client.post("/api/tools/url", json=URL_BODY, headers=auth).status_code == 200
    assert client.post("/api/tools/url", json=URL_BODY, headers=auth).status_code == 429


def test_pro_plan_is_unlimited(client, monkeypatch):
    monkeypatch.setattr(settings, "anon_daily_scan_limit", 1)
    monkeypatch.setattr(settings, "account_daily_scan_limit", 1)
    token = _register(client, {"email": "pro@example.com", "password": "StrongPass!2026-secure"})
    from app.db import SessionLocal
    from app.models import User

    db = SessionLocal()
    user = db.query(User).filter(User.email == "pro@example.com").first()
    user.plan = "pro"
    db.commit()
    db.close()
    auth = {"Authorization": f"Bearer {token}"}
    for _ in range(4):
        assert client.post("/api/tools/url", json=URL_BODY, headers=auth).status_code == 200


def test_history_reads_do_not_consume_quota(client, monkeypatch):
    monkeypatch.setattr(settings, "account_daily_scan_limit", 1)
    token = _register(client)
    auth = {"Authorization": f"Bearer {token}"}
    for _ in range(3):
        assert client.get("/api/tools/history", headers=auth).status_code == 200
    assert client.post("/api/tools/url", json=URL_BODY, headers=auth).status_code == 200


def test_free_history_retention_is_30_days(client):
    from datetime import UTC, datetime, timedelta

    from app.db import SessionLocal
    from app.models import ScanHistory, User

    token = _register(client)
    db = SessionLocal()
    user = db.query(User).filter(User.email == CREDS["email"]).first()
    db.add(ScanHistory(user_id=user.id, scan_type="url", target="old.example",
                       risk_score=10, verdict="safe",
                       created_at=datetime.now(UTC) - timedelta(days=45)))
    db.add(ScanHistory(user_id=user.id, scan_type="url", target="new.example",
                       risk_score=10, verdict="safe",
                       created_at=datetime.now(UTC) - timedelta(days=2)))
    db.commit()
    db.close()
    rows = client.get("/api/tools/history", headers={"Authorization": f"Bearer {token}"}).json()
    targets = [r["target"] for r in rows]
    assert "new.example" in targets and "old.example" not in targets


# -------------------------------------------------------------- vault cap


def test_free_vault_item_cap(client, monkeypatch):
    monkeypatch.setattr(settings, "vault_free_item_limit", 2)
    token = _register(client)
    auth = {"Authorization": f"Bearer {token}"}
    body = {"title": "t", "secret": "s3cr3t-value", "master_password": "MasterPass!2026-ok"}
    assert client.post("/api/vault", json=body, headers=auth).status_code == 201
    assert client.post("/api/vault", json=body, headers=auth).status_code == 201
    r = client.post("/api/vault", json=body, headers=auth)
    assert r.status_code == 403
    assert "20" not in r.json()["detail"] or "up to 2" in r.json()["detail"]


# ------------------------------------------------------------- HIBP gate


def test_register_refuses_breached_password(client, monkeypatch):
    from app.modules import password_lab

    async def fake_breach(password):
        return {"breached": True, "occurrences": 12345, "source": "test"}

    monkeypatch.setattr(password_lab, "breach_check", fake_breach)
    r = client.post("/api/auth/register", json={"email": "b@example.com", "password": "UniquePass!2026-xyz"})
    assert r.status_code == 400
    assert "breaches" in r.json()["detail"]


def test_register_allows_clean_password(client, monkeypatch):
    from app.modules import password_lab

    async def fake_breach(password):
        return {"breached": False, "occurrences": 0, "source": "test"}

    monkeypatch.setattr(password_lab, "breach_check", fake_breach)
    r = client.post("/api/auth/register", json={"email": "c@example.com", "password": "UniquePass!2026-xyz"})
    assert r.status_code == 201


# ------------------------------------------------------------------ MFA


def _enable_mfa(client, token, password=CREDS["password"]):
    auth = {"Authorization": f"Bearer {token}"}
    r = client.post("/api/auth/mfa/setup", json={"password": password}, headers=auth)
    assert r.status_code == 200, r.text
    mfa_key = r.json()["secret"]
    r = client.post("/api/auth/mfa/confirm", json={"code": totp_mod.current_code(mfa_key)}, headers=auth)
    assert r.status_code == 200, r.text
    return mfa_key


def test_mfa_full_flow(client):
    token = _register(client)
    mfa_key = _enable_mfa(client, token)
    # Login now returns a challenge, not tokens.
    r = client.post("/api/auth/login", json=CREDS)
    assert r.status_code == 200
    body = r.json()
    assert body["mfa_required"] is True and body["challenge"]
    assert body["access_token"] == ""
    # Wrong code is refused.
    bad = client.post("/api/auth/login/mfa", json={"challenge": body["challenge"], "code": "000000"})
    if totp_mod.current_code(mfa_key) != "000000":
        assert bad.status_code == 401
    # Correct code completes sign-in.
    ok = client.post(
        "/api/auth/login/mfa",
        json={"challenge": body["challenge"], "code": totp_mod.current_code(mfa_key)},
    )
    assert ok.status_code == 200 and ok.json()["access_token"]
    # /me reflects the state.
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {ok.json()['access_token']}"})
    assert me.json()["totp_enabled"] is True and me.json()["plan"] == "free"


def test_mfa_setup_requires_password_and_disable_works(client):
    token = _register(client)
    auth = {"Authorization": f"Bearer {token}"}
    r = client.post("/api/auth/mfa/setup", json={"password": "WrongPass!2026"}, headers=auth)
    assert r.status_code == 401
    mfa_key = _enable_mfa(client, token)
    r = client.post(
        "/api/auth/mfa/disable",
        json={"password": CREDS["password"], "code": totp_mod.current_code(mfa_key)},
        headers=auth,
    )
    assert r.status_code == 200 and r.json()["totp_enabled"] is False
    # And login is direct again.
    r = client.post("/api/auth/login", json=CREDS)
    assert r.json()["access_token"]


def test_totp_codes_are_time_bound():
    mfa_key = totp_mod.generate_secret()
    old = totp_mod._code_at(mfa_key, time.time() - 300)
    assert not totp_mod.verify(mfa_key, old)
