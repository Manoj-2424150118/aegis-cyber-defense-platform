"""Pro API keys + history export (spec §2 entitlements)."""

from datetime import UTC, datetime, timedelta

CREDS = {"email": "keys@example.com", "password": "StrongPass!2026-secure"}


def _register(client, creds=CREDS):
    r = client.post("/api/auth/register", json=creds)
    assert r.status_code == 201, r.text
    return r.json()["access_token"]


def _make_pro(email=CREDS["email"]):
    from app.db import SessionLocal
    from app.models import User

    db = SessionLocal()
    u = db.query(User).filter(User.email == email).first()
    u.plan = "pro"
    db.commit()
    db.close()


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_free_plan_cannot_create_keys(client):
    token = _register(client)
    r = client.post("/api/keys", json={"name": "ci"}, headers=_auth(token))
    assert r.status_code == 403
    assert "Pro" in r.json()["detail"]


def test_key_lifecycle_and_authentication(client):
    token = _register(client)
    _make_pro()
    r = client.post("/api/keys", json={"name": "ci"}, headers=_auth(token))
    assert r.status_code == 201, r.text
    body = r.json()
    key = body["key"]
    assert key.startswith("agk_")
    assert body["key_prefix"] == key[:12]

    # Only an HMAC is stored — the plaintext appears nowhere in the DB.
    from app.db import SessionLocal
    from app.models import ApiKey

    db = SessionLocal()
    row = db.query(ApiKey).first()
    db.close()
    assert row.key_hash != key and key not in row.key_hash

    # The key authenticates as the owner (here: history requires auth).
    assert client.get("/api/tools/history", headers={"X-API-Key": key}).status_code == 200
    # Listing never re-discloses the secret.
    listing = client.get("/api/keys", headers=_auth(token)).json()
    assert all("key" not in item for item in listing)
    assert listing[0]["key_prefix"] == key[:12]

    # Revocation takes effect immediately.
    assert client.delete(f"/api/keys/{body['id']}", headers=_auth(token)).status_code == 200
    assert client.get("/api/tools/history", headers={"X-API-Key": key}).status_code == 401
    assert client.get("/api/tools/history", headers={"X-API-Key": "agk_forged"}).status_code == 401


def test_keys_are_owner_scoped(client):
    token = _register(client)
    _make_pro()
    key_id = client.post("/api/keys", json={}, headers=_auth(token)).json()["id"]
    other = _register(client, {"email": "other@example.com", "password": "StrongPass!2026-secure"})
    assert client.delete(f"/api/keys/{key_id}", headers=_auth(other)).status_code == 404
    assert client.get("/api/keys", headers=_auth(other)).json() == []


def _seed_history(email=CREDS["email"], rows=3, age_days=0):
    from app.db import SessionLocal
    from app.models import ScanHistory, User

    db = SessionLocal()
    u = db.query(User).filter(User.email == email).first()
    for i in range(rows):
        db.add(ScanHistory(user_id=u.id, scan_type="url", target=f"https://example{i}.com",
                           risk_score=10, verdict="safe",
                           created_at=datetime.now(UTC) - timedelta(days=age_days)))
    db.commit()
    db.close()


def test_history_export_pro_only_and_complete(client):
    token = _register(client)
    _seed_history(rows=2)
    # Free: refused with the value proposition, and nothing leaks.
    r = client.get("/api/tools/history/export", headers=_auth(token))
    assert r.status_code == 403
    # Pro: full export, including rows older than the free 30-day window.
    _make_pro()
    _seed_history(rows=1, age_days=90)
    r = client.get("/api/tools/history/export", headers=_auth(token))
    assert r.status_code == 200
    assert "attachment" in r.headers.get("content-disposition", "")
    payload = r.json()
    assert payload["count"] == 3
    assert payload["account"] == CREDS["email"]
