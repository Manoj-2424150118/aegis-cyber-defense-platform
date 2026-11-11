"""Source-access layer for external enrichment (spec §2/§6).

Every third-party lookup an engine makes (RDAP today; reputation and
CT sources tomorrow) must go through here so the platform-wide rules
live in exactly one place:

* **timeout** — a lookup never blocks a scan indefinitely;
* **cache** — identical lookups inside the TTL are answered locally
  (quota is a shared budget, not a per-request entitlement);
* **circuit breaker** — after repeated failures the source is skipped
  for a cooldown instead of being hammered on every scan;
* **degrade, never fail** — any error returns ``None`` and the caller
  marks the result degraded and keeps the deterministic score.

Stdlib only: the alternative (an HTTP client dependency) buys nothing
for the small JSON directory queries this layer performs.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.request

_MAX_CACHE_ENTRIES = 512


class TTLCache:
    """Bounded in-process cache with per-entry time-to-live."""

    def __init__(self, ttl_seconds: float = 3600.0, max_entries: int = _MAX_CACHE_ENTRIES):
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._store: dict[str, tuple[float, object]] = {}
        self._lock = threading.Lock()

    def get(self, key: str):
        now = time.monotonic()
        with self._lock:
            item = self._store.get(key)
            if item is None:
                return None
            stored_at, value = item
            if now - stored_at > self.ttl:
                del self._store[key]
                return None
            return value

    def put(self, key: str, value) -> None:
        with self._lock:
            if len(self._store) >= self.max_entries:
                # Evict the oldest entry — simple and bounded.
                oldest = min(self._store, key=lambda k: self._store[k][0])
                del self._store[oldest]
            self._store[key] = (time.monotonic(), value)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


class CircuitBreaker:
    """Skip a failing source for a cooldown after N consecutive errors.

    Half-open behaviour is implicit: once the cooldown elapses a single
    trial call is allowed through; success closes the breaker again.
    """

    def __init__(self, failure_threshold: int = 3, cooldown_seconds: float = 300.0):
        self.threshold = failure_threshold
        self.cooldown = cooldown_seconds
        self._failures = 0
        self._opened_at: float | None = None
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            if self._opened_at is None:
                return True
            return (time.monotonic() - self._opened_at) >= self.cooldown

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self.threshold:
                self._opened_at = time.monotonic()


# Shared instances for the RDAP directory source.
rdap_cache = TTLCache(ttl_seconds=24 * 3600.0)
rdap_breaker = CircuitBreaker(failure_threshold=3, cooldown_seconds=300.0)


def fetch_json(url: str, *, timeout: float = 4.0, headers: dict | None = None,
               cache: TTLCache | None = None, breaker: CircuitBreaker | None = None,
               max_bytes: int = 262144) -> dict | None:
    """GET a small JSON document through the cache + breaker rules.

    Returns the parsed document, or ``None`` when the source is down,
    open-circuited or unreadable — callers treat ``None`` as *degraded*,
    never as an error worth failing the scan over.
    """
    if cache is not None:
        cached = cache.get(url)
        if cached is not None:
            return cached  # type: ignore[return-value]
    if breaker is not None and not breaker.allow():
        return None
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - callers pass fixed directory hosts only
            data = json.loads(resp.read(max_bytes))
    except Exception:
        if breaker is not None:
            breaker.record_failure()
        return None
    if breaker is not None:
        breaker.record_success()
    if cache is not None and isinstance(data, dict):
        cache.put(url, data)
    return data if isinstance(data, dict) else None
