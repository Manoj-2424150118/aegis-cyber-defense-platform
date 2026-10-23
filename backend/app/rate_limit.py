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


def client_ip(request: Request) -> str:
    """Real client IP. Behind a trusted proxy (Render, a load balancer) the
    direct peer is the proxy itself — keying limits on it would lump every
    visitor into one bucket — so honour X-Forwarded-For *only* when the
    deployment opts in via AEGIS_TRUST_PROXY."""
    if settings.trust_proxy:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/health":
            return await call_next(request)  # platform health checks are exempt
        client = client_ip(request)
        is_auth = request.url.path.startswith("/api/auth")
        limiter = auth_limiter if is_auth else general_limiter
        if not limiter.allow(f"{client}:{request.url.path if is_auth else 'general'}"):
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please slow down and try again shortly."},
                headers={"Retry-After": "60"},
            )
        return await call_next(request)
