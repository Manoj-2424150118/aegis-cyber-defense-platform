"""Security headers middleware — the same controls the Web Audit module
checks for on other people's websites, applied to this platform itself.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Permitted-Cross-Domain-Policies": "none",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Cache-Control": "no-store",
}
# API responses render nothing, so they get a fully locked-down CSP.
API_CSP = "default-src 'none'; frame-ancestors 'none'"
# The single-service demo serves the React SPA from the same origin; it needs
# same-origin scripts/styles and API connections — and nothing else.
SPA_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
)


def cache_control_for(path: str) -> str:
    """Cache policy split by surface — this is what lets the single
    service absorb traffic spikes instead of re-serving everything:

    * ``/assets/*`` are content-hashed build artefacts (a changed file
      gets a new URL), so browsers/CDNs may keep them for a year —
      repeat visits and traffic surges cost almost no origin work.
      The OG preview card is the one un-hashed asset, so it gets a day.
    * API/health/docs responses are dynamic and often sensitive: never
      stored.
    * The SPA shell itself is ``no-cache``: always revalidated, so a
      new deploy is picked up immediately while unchanged assets come
      from the browser cache.
    """
    if path.startswith("/assets/"):
        if path.endswith("og-preview-card.png"):
            return "public, max-age=86400"
        return "public, max-age=31536000, immutable"
    if path.startswith(("/api", "/health", "/docs", "/openapi")):
        return "no-store"
    return "no-cache"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        for name, value in HEADERS.items():
            if name == "Cache-Control":
                continue  # set per-surface by cache_control_for below
            response.headers.setdefault(name, value)
        is_api = request.url.path.startswith(("/api", "/health", "/docs", "/openapi"))
        response.headers["Content-Security-Policy"] = API_CSP if is_api else SPA_CSP
        response.headers["Cache-Control"] = cache_control_for(request.url.path)
        if "server" in response.headers:
            del response.headers["server"]
        return response
