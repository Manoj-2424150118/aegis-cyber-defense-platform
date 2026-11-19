"""In-process sliding-window rate limiter (per client IP + route class).

Production deployments behind multiple replicas should swap the store for
Redis; the interface (``allow(key)``) is intentionally tiny to make that a
one-file change. This dependency-free version keeps the demo self-contained
and makes the control testable.
"""

import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.config import settings


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_seconds: int = 60):
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        bucket = self._hits[key]
        while bucket and bucket[0] <= now - self.window:
            bucket.popleft()
        if len(bucket) >= self.limit:
            return False
        bucket.append(now)
        return True

    def reset(self) -> None:
        self._hits.clear()


general_limiter = SlidingWindowLimiter(settings.rate_limit_per_minute)
auth_limiter = SlidingWindowLimiter(settings.auth_rate_limit_per_minute)
fetch_limiter = SlidingWindowLimiter(settings.fetch_rate_limit_per_minute)

# Route prefixes whose handlers perform outbound network work (HTTP fetch,
# redirect tracing, DNS lookups, TLS handshakes) against user-supplied
# targets. Without a tight budget these turn the service into an anonymous
# proxy/scanner and a resource-exhaustion vector.
_FETCH_PREFIXES = (
    "/api/tools/web-audit",
    "/api/tools/url/resolve",
    "/api/tools/tls",
    "/api/tools/domain",
)
# Per-account limiter, applied inside the auth routes. Per-IP limits alone
# dilute when a platform's edge uses several proxy addresses; keying on the
# target account cannot be diluted and directly throttles credential
# stuffing against one person.
account_limiter = SlidingWindowLimiter(settings.auth_rate_limit_per_minute)

# Registration budget (F-07): at most a few account creations per hour
# per client IP, enforced inside the register route (same pattern as the
# per-account login limiter). The generic per-minute auth limit (10/min)
# still allows ~600 signups/hour/IP; this is the binding constraint.
register_limiter = SlidingWindowLimiter(settings.register_rate_limit_per_hour, window_seconds=3600)


def client_ip(request: Request) -> str:
    """Real client IP, resolved from the trusted end of the proxy chain.

    `X-Forwarded-For` is attacker-controlled at its LEFT-most entries — a
    client can prepend anything. Only the entries appended by hops we
    control are trustworthy, so strip `trusted_proxy_hops` entries from
    the RIGHT and take the entry that remains at that position. With one
    trusted proxy (Render), the received chain is
    "[client-claimed..., real client, proxy]" and hops=1 yields the real
    client. Taking the left-most entry instead (the pre-F-02 behaviour)
    let anyone mint a fresh rate-limit bucket per request by rotating
    one header value.
    """
    if settings.trust_proxy:
        hops = settings.trusted_proxy_hops
        if hops >= 1:  # fail closed: an unverifiable chain is never trusted
            forwarded = request.headers.get("x-forwarded-for", "")
            parts = [p.strip() for p in forwarded.split(",") if p.strip()]
            if len(parts) > hops:
                return parts[-hops - 1]
            if parts:
                return parts[0]
    return request.client.host if request.client else "unknown"


# Second layer for the fetch budget: a caller who presents a valid access
# token also spends from a per-account bucket, so rotating IPs (or sharing
# one NAT egress) cannot multiply an authenticated caller's fetch budget.
fetch_account_limiter = SlidingWindowLimiter(settings.fetch_rate_limit_per_minute)


def _account_key(request: Request) -> str | None:
    """User id from a valid Bearer access token, else None (anonymous)."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    from app.security import decode_token  # local import: avoids a cycle

    try:
        payload = decode_token(auth[7:].strip(), expected_type="access")
    except Exception:
        return None
    sub = payload.get("sub")
    return f"user:{sub}" if sub else None


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/health":
            return await call_next(request)  # platform health checks are exempt
        client = client_ip(request)
        is_auth = request.url.path.startswith("/api/auth")
        is_fetch = request.url.path.startswith(_FETCH_PREFIXES)
        if is_fetch:
            account_key = _account_key(request)
            if account_key and not fetch_account_limiter.allow(account_key):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many requests. Please slow down and try again shortly."},
                    headers={"Retry-After": "60"},
                )
            limiter, key = fetch_limiter, f"{client}:fetch"
        elif is_auth:
            limiter, key = auth_limiter, f"{client}:{request.url.path}"
        else:
            limiter, key = general_limiter, f"{client}:general"
        if not limiter.allow(key):
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please slow down and try again shortly."},
                headers={"Retry-After": "60"},
            )
        return await call_next(request)
