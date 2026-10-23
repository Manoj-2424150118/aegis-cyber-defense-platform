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


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        for name, value in HEADERS.items():
            response.headers.setdefault(name, value)
        is_api = request.url.path.startswith(("/api", "/health", "/docs", "/openapi"))
        response.headers["Content-Security-Policy"] = API_CSP if is_api else SPA_CSP
        if "server" in response.headers:
            del response.headers["server"]
        return response
