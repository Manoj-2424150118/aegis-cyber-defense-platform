"""External ad-network slot (spec §3): CSP-safe, consent-gated, off by
default. The backend half is verifiable here; the frontend renders the
network frame only when this config says enabled AND the visitor's
stored consent is 'third-party-allowed'."""

from app.config import settings
from app.headers import SPA_CSP, spa_csp


def test_config_reports_network_disabled_by_default(client):
    r = client.get("/api/public/config")
    assert r.status_code == 200
    assert r.json()["ads"] == {"network_enabled": False, "slot_url": None}


def test_spa_csp_unchanged_while_network_disabled(client):
    assert spa_csp() == SPA_CSP
    assert "frame-src" not in spa_csp()
    r = client.get("/pricing")  # any SPA-shell route
    assert "frame-src" not in r.headers["content-security-policy"]


def test_enabling_network_adds_only_its_frame_origin(client, monkeypatch):
    monkeypatch.setattr(settings, "ads_network_enabled", True)
    monkeypatch.setattr(settings, "ads_network_frame_src", "https://ads.example.invalid")
    monkeypatch.setattr(settings, "ads_network_slot_url", "https://ads.example.invalid/slot")
    csp = spa_csp()
    assert csp.startswith(SPA_CSP)
    assert "; frame-src 'self' https://ads.example.invalid" in csp
    assert "unsafe-inline" not in csp  # never the lazy way out
    cfg = client.get("/api/public/config").json()
    assert cfg["ads"] == {"network_enabled": True, "slot_url": "https://ads.example.invalid/slot"}


def test_http_frame_origin_is_refused(client, monkeypatch):
    # A plaintext origin must never make it into the CSP.
    monkeypatch.setattr(settings, "ads_network_enabled", True)
    monkeypatch.setattr(settings, "ads_network_frame_src", "http://ads.example.invalid")
    assert spa_csp() == SPA_CSP
