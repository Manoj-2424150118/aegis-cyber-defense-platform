"""F-02 / F-03 hardening: the rate limiter must key on the real client,
resolved from the TRUSTED end of the X-Forwarded-For chain.

Before this fix, client_ip() took the LEFT-most XFF entry — the one the
client itself controls — so rotating one header value minted a fresh
12/min fetch bucket per request (verified live, 2026-11-11: 16 rotating
requests, 16x 200, 0x 429).
"""

import logging

import pytest
from pydantic import ValidationError
from starlette.requests import Request

from app.config import Settings, settings
from app.rate_limit import client_ip

PEER = "203.0.113.254"  # the socket peer (the trusted proxy, in deployment)


def _request(xff: str | None = None) -> Request:
    headers = [(b"x-forwarded-for", xff.encode())] if xff is not None else []
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/tools/web-audit",
            "headers": headers,
            "client": (PEER, 5000),
            "server": ("testserver", 80),
            "scheme": "http",
            "query_string": b"",
        }
    )


@pytest.fixture()
def trust_on(monkeypatch):
    monkeypatch.setattr(settings, "trust_proxy", True)
    monkeypatch.setattr(settings, "trusted_proxy_hops", 1)


def test_chain_two_entries_hops_one_takes_client_not_proxy(trust_on):
    # Spec case: "1.1.1.1, 2.2.2.2" with 1 trusted hop -> 1.1.1.1 (the last
    # entry is the proxy itself, not the client).
    assert client_ip(_request("1.1.1.1, 2.2.2.2")) == "1.1.1.1"


def test_rotating_spoofed_left_entries_cannot_change_bucket(trust_on):
    # Attacker prepends rotating junk; the trusted tail is constant, so the
    # resolved client — and therefore the rate-limit bucket — is stable.
    a = client_ip(_request("203.0.113.1, 198.51.100.10, 10.0.0.254"))
    b = client_ip(_request("203.0.113.99, 198.51.100.10, 10.0.0.254"))
    c = client_ip(_request("192.0.2.7, 198.51.100.10, 10.0.0.254"))
    assert a == b == c == "198.51.100.10"


def test_single_entry_chain_is_the_client(trust_on):
    assert client_ip(_request("198.51.100.23")) == "198.51.100.23"


def test_no_header_falls_back_to_socket_peer(trust_on):
    assert client_ip(_request(None)) == PEER


def test_header_ignored_when_trust_proxy_off(monkeypatch):
    monkeypatch.setattr(settings, "trust_proxy", False)
    assert client_ip(_request("1.1.1.1, 2.2.2.2")) == PEER


def test_zero_hops_fails_closed_to_socket_peer(monkeypatch):
    # Defense in depth behind the startup validator: even if the setting is
    # forced post-hoc, an unverifiable chain is never trusted.
    monkeypatch.setattr(settings, "trust_proxy", True)
    monkeypatch.setattr(settings, "trusted_proxy_hops", 0)
    assert client_ip(_request("1.1.1.1, 2.2.2.2")) == PEER


def test_settings_refuse_trust_proxy_without_hops():
    # F-03: startup must refuse an unverifiable proxy chain.
    with pytest.raises(ValidationError):
        Settings(trust_proxy=True, trusted_proxy_hops=0)
    with pytest.raises(ValidationError):
        Settings(trust_proxy=True, trusted_proxy_hops=-2)
    # Safe combinations construct fine.
    Settings(trust_proxy=True, trusted_proxy_hops=1)
    Settings(trust_proxy=False, trusted_proxy_hops=0)


def test_rotating_xff_hits_fetch_rate_limit(client, trust_on):
    """HTTP-level (spec §6 check 3): 30 requests whose attacker-controlled
    left XFF entries rotate while the trusted tail stays constant must hit
    the 12/min fetch budget — at least one 429. The URL is a loopback the
    guard rejects with 400, so no outbound fetch happens; the limiter runs
    in middleware before the handler and counts every attempt."""
    statuses = []
    for n in range(30):
        r = client.post(
            "/api/tools/web-audit",
            json={"url": "http://127.0.0.1/"},
            headers={"X-Forwarded-For": f"203.0.113.{n}, 198.51.100.10, 10.0.0.254"},
        )
        statuses.append(r.status_code)
    assert 429 in statuses, f"no 429 in {statuses}"
    assert statuses.index(429) == 12  # exactly the 13th request onward


def test_startup_logs_ip_source(caplog):
    # F-03: the resolved client-IP source is logged once at startup
    # (entering the TestClient context runs the lifespan).
    from fastapi.testclient import TestClient

    from app.main import app

    with caplog.at_level(logging.INFO, logger="aegis"):
        with TestClient(app):
            pass
    assert any(
        "rate-limit client IP source" in rec.message for rec in caplog.records
    )
