"""Traffic-readiness tests: gzip for payloads, split cache policy.

These pin the behaviour that lets one small service absorb spikes:
hashed assets are cached for a year by browsers, the SPA shell is
revalidated, API responses are never stored, and the live SSE streams
are never gzip-buffered.
"""

from app.headers import cache_control_for


def test_cache_policy_split():
    assert cache_control_for("/assets/index-abc123.js") == "public, max-age=31536000, immutable"
    assert cache_control_for("/assets/index-abc123.css") == "public, max-age=31536000, immutable"
    assert cache_control_for("/assets/og-preview-card.png") == "public, max-age=86400"
    assert cache_control_for("/api/tools/url") == "no-store"
    assert cache_control_for("/health") == "no-store"
    assert cache_control_for("/") == "no-cache"


def test_api_responses_no_store_live(client):
    r = client.get("/health")
    assert r.headers["cache-control"] == "no-store"


def test_gzip_applied_to_large_responses(client):
    r = client.get("/openapi.json", headers={"Accept-Encoding": "gzip"})
    assert r.headers.get("content-encoding") == "gzip"
    assert r.json()["info"]["title"]  # body still decodes to valid JSON


def test_sse_stream_is_never_gzipped(client):
    r = client.post(
        "/api/tools/password/stream",
        json={"password": "password123"},
        headers={"Accept-Encoding": "gzip"},
    )
    assert r.headers["content-type"].startswith("text/event-stream")
    assert "gzip" not in r.headers.get("content-encoding", "")
    assert '"type": "start"' in r.text or '"type":"start"' in r.text or "start" in r.text
