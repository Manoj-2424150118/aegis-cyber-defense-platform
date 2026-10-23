CREDS = {"email": "manoj@example.com", "password": "StrongPass!2026-secure"}


def _register(client):
    return client.post("/api/auth/register", json=CREDS)


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_security_headers_present(client):
    r = client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "strict-transport-security" in r.headers


def test_register_login_and_vault_flow(client):
    r = _register(client)
    assert r.status_code == 201
    token = r.json()["access_token"]
    auth = {"Authorization": f"Bearer {token}"}
    created = client.post(
        "/api/vault",
        json={"title": "Bank", "secret": "account 12345", "master_password": "MasterPass!2026-ok"},
        headers=auth,
    )
    assert created.status_code == 201
    item_id = created.json()["id"]
    listed = client.get("/api/vault", headers=auth)
    assert len(listed.json()) == 1
    assert "account" not in str(listed.json())  # titles only — no secret leakage in lists
    opened = client.post(f"/api/vault/{item_id}/open", json={"master_password": "MasterPass!2026-ok"}, headers=auth)
    assert opened.json()["secret"] == "account 12345"
    wrong = client.post(f"/api/vault/{item_id}/open", json={"master_password": "WrongMaster!2026-x"}, headers=auth)
    assert wrong.status_code == 400


def test_vault_requires_auth(client):
    assert client.get("/api/vault").status_code == 401


def test_login_lockout_after_failures(client):
    _register(client)
    for _ in range(5):
        r = client.post("/api/auth/login", json={"email": CREDS["email"], "password": "wrong-password"})
        assert r.status_code in (401, 423)
    r = client.post("/api/auth/login", json=CREDS)
    assert r.status_code == 423  # locked even with the correct password


def test_url_tool_endpoint(client):
    r = client.post("/api/tools/url", json={"url": "http://192.168.1.9/paypal/login"})
    assert r.status_code == 200
    assert r.json()["risk_score"] >= 50


def test_password_tools(client):
    r = client.post("/api/tools/password/assess", json={"password": "123456"})
    assert r.json()["is_common_password"] is True
    g = client.post("/api/tools/password/generate", json={"length": 24, "symbols": True})
    assert len(g.json()["password"]) == 24


def test_file_tool_endpoint(client):
    r = client.post("/api/tools/file", files={"file": ("hello.txt", b"just some text", "text/plain")})
    assert r.status_code == 200
    assert r.json()["verdict"] == "clean"


def test_validation_rejects_short_password_registration(client):
    r = client.post("/api/auth/register", json={"email": "a@b.com", "password": "short"})
    assert r.status_code == 422
