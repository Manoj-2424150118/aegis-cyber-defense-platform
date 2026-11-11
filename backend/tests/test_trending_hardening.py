"""F-04 — trending-aggregate integrity, second layer.

The v1.8.1 burst cap stops ONE source repeating one payload (3/min).
What it cannot stop is many sources (or one patient source) jointly
inflating a single domain into the public lists. These tests prove the
global per-signature ceiling (20/hour, source-independent) and the
30-day retention prune.
"""

from datetime import UTC, datetime, timedelta

import pytest

from app.config import settings
from app.db import SessionLocal
from app.models import ScanEvent

PHISH = {"url": "http://paypa1-secure-login.xyz/verify?account=suspended"}


@pytest.fixture(autouse=True)
def _trust_proxy(monkeypatch):
    # Distinct sources are only distinguishable when the proxy chain is
    # trusted (the repo pattern: tests opt in explicitly, production
    # defaults to not trusting X-Forwarded-For).
    monkeypatch.setattr(settings, "trust_proxy", True)


def _post_from(client, payload, ip):
    # Two-entry chain: the entry Render appends (right) is stripped by
    # the trusted-hops rule, leaving the distinct originating source.
    # (A one-entry chain cannot be verified and fails closed to the
    # shared socket peer — that is F-02 working as intended.)
    return client.post(
        "/api/tools/url", json=payload,
        headers={"X-Forwarded-For": f"{ip}, 203.0.113.254"},
    )


def test_global_signature_ceiling_caps_cross_source_inflation(client):
    # 25 distinct sources submit the same phish — each is far under the
    # per-source burst cap, so only the global ceiling can stop this.
    for i in range(25):
        resp = _post_from(client, PHISH, f"198.51.100.{i + 1}")
        assert resp.status_code == 200
    out = client.get("/api/public/trending").json()
    assert out["flagged"] == 20
    assert out["top_flagged_domains"][0] == {
        "domain": "paypa1-secure-login.xyz",
        "count": 20,
    }
    assert out["top_impersonated_brands"][0]["count"] == 20


def test_signature_ceiling_is_per_signature_not_global_lockout(client):
    # Saturating one signature must not suppress a different one.
    for i in range(22):
        _post_from(client, PHISH, f"198.51.100.{i + 1}")
    before = client.get("/api/public/trending").json()["flagged"]
    assert before == 20  # first signature is capped
    other = {"url": "http://secure-paypa1-login.xyz/verify?account=suspended"}
    resp = _post_from(client, other, "198.51.100.200")
    assert resp.status_code == 200
    # (top_flagged_domains only lists domains with count >= 2, so the
    # proof is the flagged total moving by exactly one.)
    from app.routers import tools as tools_router

    tools_router._trending_cache = None  # bypass the response cache
    after = client.get("/api/public/trending").json()["flagged"]
    assert after == before + 1


def test_old_events_fall_out_of_the_window_and_get_pruned(client):
    db = SessionLocal()
    try:
        db.add(ScanEvent(
            scan_type="url", verdict="malicious", risk_score=90,
            domain="old-phish.example", brand=None, finding_codes="brand-in-host",
            created_at=datetime.now(UTC) - timedelta(days=31),
        ))
        db.commit()
    finally:
        db.close()

    # The public window already excludes the stale row...
    out = client.get("/api/public/trending").json()
    assert out["total_scans"] == 0

    # ...and the next recorded scan prunes it from storage entirely.
    client.post("/api/tools/url", json={"url": "https://www.google.com"})
    db = SessionLocal()
    try:
        remaining = db.query(ScanEvent).all()
    finally:
        db.close()
    assert len(remaining) == 1
    assert remaining[0].domain is None  # the fresh safe scan, not the stale phish
