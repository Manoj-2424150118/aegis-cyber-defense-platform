"""Domain monitoring (spec §2): plan limits + change detection."""

import pytest

from app.modules import domain_checker

CREDS = {"email": "watcher@example.com", "password": "StrongPass!2026-secure"}


def _register(client, creds=CREDS):
    r = client.post("/api/auth/register", json=creds)
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _make_pro(email=CREDS["email"]):
    from app.db import SessionLocal
    from app.models import User

    db = SessionLocal()
    u = db.query(User).filter(User.email == email).first()
    u.plan = "pro"
    db.commit()
    db.close()


def test_monitoring_requires_account(client):
    assert client.get("/api/monitoring").status_code == 401
    assert client.post("/api/monitoring", json={"domain": "example.com"}).status_code == 401


def test_free_plan_limit_is_one(client):
    auth = _register(client)
    r = client.post("/api/monitoring", json={"domain": "https://example.com/path"}, headers=auth)
    assert r.status_code == 201, r.text
    assert r.json()["domain"] == "example.com"  # normalised to the host
    r = client.post("/api/monitoring", json={"domain": "example.org"}, headers=auth)
    assert r.status_code == 403
    assert "Pro" in r.json()["detail"]
    # Duplicate add is a no-op return, not an error or a second slot.
    r = client.post("/api/monitoring", json={"domain": "example.com"}, headers=auth)
    assert r.status_code == 201
    assert len(client.get("/api/monitoring", headers=auth).json()) == 1


def test_invalid_domain_rejected(client):
    auth = _register(client)
    assert client.post("/api/monitoring", json={"domain": "not a domain"}, headers=auth).status_code == 400


def test_check_records_grade_and_flags_change(client, monkeypatch):
    auth = _register(client)
    mid = client.post("/api/monitoring", json={"domain": "example.com"}, headers=auth).json()["id"]
    monkeypatch.setattr(domain_checker, "check_domain",
                        lambda d: {"domain": d, "score": 92, "grade": "A", "findings": []})
    r = client.post(f"/api/monitoring/{mid}/check", headers=auth)
    assert r.status_code == 200
    assert r.json()["last_grade"] == "A"
    assert r.json()["change_detected"] is False  # first sighting is a baseline
    monkeypatch.setattr(domain_checker, "check_domain",
                        lambda d: {"domain": d, "score": 40, "grade": "D", "findings": [{"code": "DMARC_MISSING"}]})
    r = client.post(f"/api/monitoring/{mid}/check", headers=auth)
    assert r.json()["last_grade"] == "D"
    assert r.json()["change_detected"] is True
    assert r.json()["findings"]


def test_pro_limit_is_ten_and_rows_are_owner_scoped(client):
    auth = _register(client)
    _make_pro()
    for i in range(10):
        r = client.post("/api/monitoring", json={"domain": f"site{i}.example.com"}, headers=auth)
        assert r.status_code == 201, r.text
    assert client.post("/api/monitoring", json={"domain": "site10.example.com"},
                       headers=auth).status_code == 403
    other = _register(client, {"email": "snoop@example.com", "password": "StrongPass!2026-secure"})
    assert client.get("/api/monitoring", headers=other).json() == []
    first_id = client.get("/api/monitoring", headers=auth).json()[0]["id"]
    assert client.delete(f"/api/monitoring/{first_id}", headers=other).status_code == 404
    assert client.delete(f"/api/monitoring/{first_id}", headers=auth).status_code == 200
