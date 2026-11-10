"""v1.8.1 hardening — regression tests for the external audit findings.

Covers: fetch-endpoint rate limits (H-1), trending integrity — strict
domain normalisation, flagged-only brands, per-source burst cap (M-1,
M-4), upload early 413 (M-2), and the HttpOnly refresh-cookie session
model (M-6).
"""

from app.modules.url_analyzer import registrable_domain

STRONG = "Demo!Vault#2026"


# ── M-4: registrable_domain must reject non-domains ──────────────────

def test_registrable_domain_rejects_ip_literals_and_junk():
    assert registrable_domain("http://10.5.0.1/login") is None
    assert registrable_domain("http://10.5/") is None
    assert registrable_domain("http://127.0.0.1:8080/x") is None
    assert registrable_domain("javascript:alert(1)") is None
    assert registrable_domain("data:text/html;base64,AAAA") is None
    assert registrable_domain("https://paypa1-secure-login.xyz/verify") == "paypa1-secure-login.xyz"
    assert registrable_domain("https://sub.example.co.uk/x") is None or registrable_domain(
        "https://sub.example.co.uk/x") == "co.uk"  # last-two-labels rule, still a valid domain


# ── M-1: brands recorded only for flagged verdicts; burst cap works ──

def test_safe_scan_with_brand_lookalike_not_in_trending(client):
    # A *safe*-verdict scan whose host merely contains a brand string
    # must not surface in the public impersonated-brands aggregate.
    client.post("/api/tools/url", json={"url": "https://www.google.com"})
    out = client.get("/api/public/trending").json()
    assert all(b["name"] != "google" for b in out["top_impersonated_brands"])


def test_burst_cap_limits_identical_flagged_events(client):
    phish = {"url": "http://paypa1-secure-login.xyz/verify?account=suspended"}
    for _ in range(6):
        client.post("/api/tools/url", json=phish)
    out = client.get("/api/public/trending").json()
    # First 3 identical events from one source count; the burst is capped.
    assert out["flagged"] == 3
    assert out["top_impersonated_brands"][0]["count"] == 3


# ── H-1: fetch endpoints have a tight per-IP budget ──────────────────

def test_fetch_endpoints_rate_limited(client):
    statuses = [
        client.post("/api/tools/domain", json={"domain": "not a domain!!"}).status_code
        for _ in range(15)
    ]
    assert 429 in statuses, statuses
    assert statuses.index(429) >= 10  # not instant — a real budget exists first


# ── M-2: oversized upload rejected (declared length, early 413) ──────

def test_oversized_upload_rejected_413(client):
    big = b"A" * (10 * 1024 * 1024 + 1)
    r = client.post("/api/tools/file", files={"file": ("big.bin", big)})
    assert r.status_code == 413


# ── M-6: refresh token cookie flow ───────────────────────────────────

def test_refresh_cookie_set_and_used(client):
    r = client.post("/api/auth/register", json={"email": "cookie@example.com", "password": STRONG})
    assert r.status_code == 201
    set_cookie = r.headers.get("set-cookie", "")
    assert "aegis_refresh=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=strict" in set_cookie

    # Cookie refresh without the required custom header is refused.
    r2 = client.post("/api/auth/refresh", json={})
    assert r2.status_code == 401

    # With the header, the cookie mints a working access token.
    r3 = client.post("/api/auth/refresh", json={}, headers={"X-Aegis-Refresh": "1"})
    assert r3.status_code == 200
    token = r3.json()["access_token"]
    assert client.get("/api/vault", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_logout_clears_refresh_cookie(client):
    client.post("/api/auth/register", json={"email": "out@example.com", "password": STRONG})
    r = client.post("/api/auth/logout")
    assert r.status_code == 200
    assert "aegis_refresh=" in r.headers.get("set-cookie", "")
    # Cookie jar cleared → cookie-based refresh no longer possible.
    r2 = client.post("/api/auth/refresh", json={}, headers={"X-Aegis-Refresh": "1"})
    assert r2.status_code == 401


def test_body_refresh_still_works_for_api_clients(client):
    r = client.post("/api/auth/register", json={"email": "api@example.com", "password": STRONG})
    refresh = r.json()["refresh_token"]
    client.cookies.clear()
    r2 = client.post("/api/auth/refresh", json={"refresh_token": refresh})
    assert r2.status_code == 200
