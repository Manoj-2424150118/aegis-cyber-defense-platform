"""F-07 — registration needs an hourly budget, not a per-minute one.

The generic auth limiter allows 10 requests/minute/IP — roughly 600
account creations an hour, i.e. no meaningful barrier to farming
accounts. Registration now spends from a 3/hour per-IP budget, keyed on
the F-02-hardened client_ip(), checked before any other work.
"""

from app.config import settings

STRONG = "Demo!Vault#2026"


def _register(client, n, **kwargs):
    return client.post(
        "/api/auth/register",
        json={"email": f"user{n}@example.com", "password": STRONG},
        **kwargs,
    )


def test_fourth_registration_from_one_ip_is_429(client):
    for i in range(settings.register_rate_limit_per_hour):
        assert _register(client, i).status_code == 201
    resp = _register(client, 99)
    assert resp.status_code == 429
    assert "hour" in resp.json()["detail"]


def test_registration_budget_is_per_ip(client, monkeypatch):
    monkeypatch.setattr(settings, "trust_proxy", True)
    for i in range(settings.register_rate_limit_per_hour):
        assert _register(
            client, i, headers={"X-Forwarded-For": "198.51.100.9, 203.0.113.254"}
        ).status_code == 201
    assert _register(
        client, 50, headers={"X-Forwarded-For": "198.51.100.9, 203.0.113.254"}
    ).status_code == 429
    # A different source still has its own budget.
    assert _register(
        client, 51, headers={"X-Forwarded-For": "198.51.100.10, 203.0.113.254"}
    ).status_code == 201


def test_xff_rotation_does_not_dodge_the_budget(client, monkeypatch):
    # With the trusted hop stripped, rotating the client-claimed left
    # entries changes nothing: the budget key stays the real client.
    monkeypatch.setattr(settings, "trust_proxy", True)
    for i in range(settings.register_rate_limit_per_hour):
        assert _register(
            client, i,
            headers={"X-Forwarded-For": f"10.0.0.{i}, 198.51.100.9, 203.0.113.254"},
        ).status_code == 201
    assert _register(
        client, 77,
        headers={"X-Forwarded-For": "10.9.9.9, 198.51.100.9, 203.0.113.254"},
    ).status_code == 429
