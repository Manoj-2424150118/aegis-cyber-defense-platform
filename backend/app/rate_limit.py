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


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client = request.client.host if request.client else "unknown"
        is_auth = request.url.path.startswith("/api/auth")
        limiter = auth_limiter if is_auth else general_limiter
        if not limiter.allow(f"{client}:{request.url.path if is_auth else 'general'}"):
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please slow down and try again shortly."},
                headers={"Retry-After": "60"},
            )
        return await call_next(request)
