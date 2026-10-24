"""Aegis — Personal Cyber Defense Platform (API entry point).

Run locally:  uvicorn app.main:app --reload --port 8000
Interactive docs: http://localhost:8000/docs
"""

import logging
import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings
from app.db import init_db
from app.headers import SecurityHeadersMiddleware
from app.rate_limit import RateLimitMiddleware
from app.routers import auth, tools, vault_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("aegis")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a request id for support/log correlation; never log bodies,
    passwords or tokens."""

    async def dispatch(self, request: Request, call_next):
        request_id = uuid.uuid4().hex[:12]
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        logger.info("%s %s -> %s [%s]", request.method, request.url.path, response.status_code, request_id)
        return response

THREAT_MODEL = [
    {"threat": "Phishing links & fake login pages", "module": "URL Analyser", "endpoint": "POST /api/tools/url"},
    {"threat": "Phishing / BEC emails", "module": "Email Analyser", "endpoint": "POST /api/tools/email"},
    {"threat": "Malware & ransomware attachments", "module": "File Scanner", "endpoint": "POST /api/tools/file"},
    {"threat": "Weak / reused passwords", "module": "Password Lab", "endpoint": "POST /api/tools/password/assess"},
    {"threat": "Credential stuffing after breaches", "module": "Breach Check (k-anonymity)", "endpoint": "POST /api/tools/password/breach"},
    {"threat": "Theft of stored secrets", "module": "Encrypted Vault (AES-256-GCM)", "endpoint": "/api/vault"},
    {"threat": "MITM / unsafe websites", "module": "Website Audit (TLS & headers)", "endpoint": "POST /api/tools/web-audit"},
    {"threat": "Brute force against Aegis itself", "module": "Argon2id + lockout + rate limiting", "endpoint": "/api/auth/*"},
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title=settings.app_name,
    version="1.4.0",
    description="One platform that protects an individual user against today's most common cyber threats — phishing, malware, credential theft, weak passwords and unsafe websites.",
    lifespan=lifespan,
)
app.add_middleware(RequestContextMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Last-resort handler: log the fault server-side, return a generic
    message — stack traces and internals never reach the client."""
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error. Please try again."})
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(auth.router)
app.include_router(tools.router)
app.include_router(vault_router.router)


@app.get("/health", tags=["ops"])
def health():
    return {"status": "ok", "service": "aegis-api", "version": "1.4.0"}


@app.get("/api", tags=["ops"])
def root():
    return {
        "name": settings.app_name,
        "docs": "/docs",
        "threat_coverage": THREAT_MODEL,
    }


# --- Single-service demo mode -------------------------------------------------
# When a built frontend is present (AEGIS_STATIC_DIR or ./static next to the
# backend), serve the SPA from the same origin so the whole platform deploys
# as ONE free-tier web service. API routes above always take precedence.
_STATIC_DIR = Path(os.environ.get("AEGIS_STATIC_DIR", Path(__file__).resolve().parents[1] / "static"))
if _STATIC_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=_STATIC_DIR / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa_fallback(path: str):
        candidate = _STATIC_DIR / path
        if path and candidate.is_file():
            return FileResponse(candidate)
        index = _STATIC_DIR / "index.html"
        if index.is_file():
            return FileResponse(index)
        raise HTTPException(404, "Not found.")
else:

    @app.get("/", tags=["ops"])
    def api_only_root():
        return root()
