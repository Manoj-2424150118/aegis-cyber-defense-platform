"""Security-tools router — the six Aegis protection modules as APIs.

Analysis endpoints work without an account (a person who just received a
suspicious link should not need to register to check it). When a user is
logged in, scans are saved to their history for the dashboard.
"""

import logging
from collections import Counter
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app import streaming
from app.config import settings
from app.db import SessionLocal, get_db
from app.deps import get_current_user
from app.models import ScanEvent, ScanHistory, User
from app.modules import (
    domain_checker,
    email_analyzer,
    file_scanner,
    message_analyzer,
    password_lab,
    redirect_tracer,
    tls_inspector,
    url_analyzer,
    web_audit,
)
from app.schemas import (
    DomainRequest,
    EmailRequest,
    GenerateRequest,
    MessageRequest,
    PasswordRequest,
    TlsRequest,
    UrlRequest,
    WebAuditRequest,
)
from app.validation import host_from_url, is_valid_domain, is_valid_host

logger = logging.getLogger("aegis.tools")

router = APIRouter(prefix="/api/tools", tags=["tools"])


def _record(db: Session, user: User | None, scan_type: str, target: str, score: int, verdict: str) -> None:
    if user is None:
        return
    db.add(ScanHistory(user_id=user.id, scan_type=scan_type, target=target[:500], risk_score=score, verdict=verdict))
    db.commit()


def _optional_user(db: Session = Depends(get_db)):
    return None  # anonymous by default; history is recorded via /api/history for logged-in clients


_FLAGGED = ("suspicious", "malicious")


def _record_event(scan_type: str, verdict: str, risk_score: int, domain: str | None = None,
                  brand: str | None = None, codes: tuple[str, ...] | list[str] = ()) -> None:
    """Store one privacy-safe aggregate event for the Trends view.

    The flagged domain is kept only for suspicious/malicious verdicts —
    the domains people check on safe links are nobody's business.
    Telemetry must never break a scan, so every failure is swallowed.
    """
    try:
        db = SessionLocal()
        try:
            db.add(ScanEvent(
                scan_type=scan_type, verdict=verdict, risk_score=risk_score,
                domain=domain if verdict in _FLAGGED else None,
                brand=brand, finding_codes=",".join(codes)[:500],
            ))
            db.commit()
        finally:
            db.close()
    except Exception:
        logger.debug("scan-event recording failed", exc_info=True)


def _record_url_event(raw_url: str, report) -> None:
    _record_event(
        "url", report.verdict, report.risk_score,
        domain=url_analyzer.registrable_domain(raw_url),
        brand=url_analyzer.impersonated_brand(raw_url),
        codes=[f["code"] for f in report.findings],
    )


@router.post("/url")
async def check_url(body: UrlRequest):
    report = url_analyzer.analyze_url(body.url)
    _record_url_event(body.url, report)
    return report.as_dict()


@router.post("/url/resolve")
async def resolve_url(body: UrlRequest):
    """Follow a link's redirect chain (SSRF-guarded on every hop) and
    score the final destination — the page a victim would really reach."""
    try:
        return await run_in_threadpool(redirect_tracer.trace_redirects, body.url)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None


@router.post("/password/assess")
async def assess(body: PasswordRequest):
    return password_lab.assess_password(body.password)


@router.post("/password/breach")
async def breach(body: PasswordRequest):
    return await password_lab.breach_check(body.password)


@router.post("/password/generate")
async def generate(body: GenerateRequest):
    return {
        "password": password_lab.generate_password(body.length, body.symbols),
        "passphrase": password_lab.generate_passphrase(),
    }


async def _read_upload_capped(file: UploadFile) -> bytes:
    # Chunked, capped read: never buffer an unbounded upload in memory
    # (a multi-GB "file" must not be able to OOM the service).
    limit = settings.max_upload_bytes
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise HTTPException(413, f"File exceeds the {limit // (1024 * 1024)} MB scanning limit.")
        chunks.append(chunk)
    data = b"".join(chunks)
    if not data:
        raise HTTPException(400, "Empty file.")
    return data


@router.post("/file")
async def scan_upload(file: UploadFile = File(...)):
    data = await _read_upload_capped(file)
    return file_scanner.scan_file(file.filename or "upload", data)


@router.post("/email")
async def check_email(body: EmailRequest):
    if not body.headers.strip() and not body.body.strip():
        raise HTTPException(400, "Provide email headers, body, or both.")
    result = email_analyzer.analyze_email(body.headers, body.body)
    _record_event("email", result["verdict"], result["risk_score"],
                  domain=result.get("from_domain") or None,
                  codes=[f["code"] for f in result["findings"]])
    return result


@router.post("/web-audit")
async def audit(body: WebAuditRequest):
    try:
        # audit_website does blocking network I/O (up to its 8s timeout).
        # Run it in the threadpool: calling it inline would freeze the
        # event loop — and an audit of THIS service would deadlock
        # against itself until timeout.
        return await run_in_threadpool(web_audit.audit_website, body.url)
    except ValueError as exc:
        # SSRF guard and scheme validation land here — a clean 400, never a 500.
        raise HTTPException(400, str(exc)) from None


@router.post("/message")
async def check_message(body: MessageRequest):
    if not body.text.strip():
        raise HTTPException(400, "Paste a message to check.")
    result = message_analyzer.analyze_message(body.text)
    _record_event("message", result["verdict"], result["risk_score"],
                  codes=[f["code"] for f in result["findings"]])
    return result


def _checked_domain(raw: str) -> str:
    host = host_from_url(raw)
    if not is_valid_domain(host):
        raise HTTPException(400, f"'{host or raw}' is not a valid domain name.")
    return host


@router.post("/domain")
async def check_domain(body: DomainRequest):
    domain = _checked_domain(body.domain)
    # DNS lookups block; keep them off the event loop.
    return await run_in_threadpool(domain_checker.check_domain, domain)


@router.post("/tls")
async def check_tls(body: TlsRequest):
    host = host_from_url(body.host)
    if not is_valid_host(host):
        raise HTTPException(400, f"'{host or body.host}' is not a valid domain name or IP address.")
    try:
        # TLS handshakes block; run in the threadpool like the audit.
        return await run_in_threadpool(tls_inspector.inspect_tls, host)
    except ValueError as exc:
        # SSRF guard (non-public hosts) — a clean 400, never a 500.
        raise HTTPException(400, str(exc)) from None


# ── Live-streamed analysis (Server-Sent Events) ──────────────────────
# Same engines, executed stage-by-stage so the UI can show the agent's
# work as it happens. Final event payload == classic endpoint payload.

_SSE_HEADERS = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}


@router.post("/url/stream")
async def check_url_stream(body: UrlRequest):
    async def gen():
        async for chunk in streaming.stream_url(body.url):
            yield chunk
        _record_url_event(body.url, url_analyzer.analyze_url(body.url))

    return StreamingResponse(gen(), media_type="text/event-stream", headers=_SSE_HEADERS)


@router.post("/email/stream")
async def check_email_stream(body: EmailRequest):
    if not body.headers.strip() and not body.body.strip():
        raise HTTPException(400, "Provide email headers, body, or both.")

    async def gen():
        async for chunk in streaming.stream_email(body.headers, body.body):
            yield chunk
        result = email_analyzer.analyze_email(body.headers, body.body)
        _record_event("email", result["verdict"], result["risk_score"],
                      domain=result.get("from_domain") or None,
                      codes=[f["code"] for f in result["findings"]])

    return StreamingResponse(gen(), media_type="text/event-stream", headers=_SSE_HEADERS)


@router.post("/file/stream")
async def scan_upload_stream(file: UploadFile = File(...)):
    data = await _read_upload_capped(file)
    return StreamingResponse(streaming.stream_file(file.filename or "upload", data), media_type="text/event-stream", headers=_SSE_HEADERS)


@router.post("/password/stream")
async def password_stream(body: PasswordRequest):
    return StreamingResponse(streaming.stream_password(body.password), media_type="text/event-stream", headers=_SSE_HEADERS)


@router.post("/web-audit/stream")
async def audit_stream(body: WebAuditRequest):
    return StreamingResponse(streaming.stream_web_audit(body.url), media_type="text/event-stream", headers=_SSE_HEADERS)


@router.post("/message/stream")
async def check_message_stream(body: MessageRequest):
    if not body.text.strip():
        raise HTTPException(400, "Paste a message to check.")

    async def gen():
        async for chunk in streaming.stream_message(body.text):
            yield chunk
        result = message_analyzer.analyze_message(body.text)
        _record_event("message", result["verdict"], result["risk_score"],
                      codes=[f["code"] for f in result["findings"]])

    return StreamingResponse(gen(), media_type="text/event-stream", headers=_SSE_HEADERS)


@router.post("/domain/stream")
async def check_domain_stream(body: DomainRequest):
    domain = _checked_domain(body.domain)
    return StreamingResponse(streaming.stream_domain(domain), media_type="text/event-stream", headers=_SSE_HEADERS)


@router.post("/tls/stream")
async def check_tls_stream(body: TlsRequest):
    host = host_from_url(body.host)
    if not is_valid_host(host):
        raise HTTPException(400, f"'{host or body.host}' is not a valid domain name or IP address.")
    return StreamingResponse(streaming.stream_tls(host), media_type="text/event-stream", headers=_SSE_HEADERS)


# ── Public trends ────────────────────────────────────────────────────
# What the platform's own checks are seeing right now: which brands are
# being impersonated, which scam patterns repeat, which flagged domains
# keep coming back. Built only from ScanEvent aggregates (see models) —
# no submitted links, messages or addresses are ever exposed here.

public_router = APIRouter(tags=["public"])

_PATTERN_LABELS = {
    "brand-in-host": "Fake brand login pages",
    "typosquat": "Typosquatted look-alike domains",
    "credential-bait": "Messages asking for passwords / OTPs",
    "urgency-pressure": "Urgency pressure tactics",
    "bec-wire": "Payment-diversion (BEC) language",
    "giftcard-scam": "Gift-card / crypto payment demands",
    "ip-host": "Pages hosted on raw IP addresses",
    "obfuscated-ip": "Disguised IP addresses",
    "tracking-pixel": "Email open-tracking beacons",
    "hidden-text": "Hidden text to fool spam filters",
    "reply-to-mismatch": "Reply-To hijacking",
    "spf-fail": "Forged sender authentication (SPF)",
    "dkim-fail": "Forged sender authentication (DKIM)",
    "dmarc-fail": "Forged sender authentication (DMARC)",
    "executable-download": "Program downloads sent as links",
    "shortener": "Shortened links hiding destinations",
    "tracking-wrapper": "Tracking redirect wrappers",
    "tracking-params": "Click-tracking parameters (utm / click IDs)",
    "wrapped-destination": "Destinations hidden inside wrapper links",
    "punycode": "Punycode look-alike domains",
}


def _as_utc(ts: datetime | None) -> datetime | None:
    # SQLite returns offset-naive datetimes even for timezone-aware
    # columns; stored values are UTC by construction (models._now).
    if ts is not None and ts.tzinfo is None:
        return ts.replace(tzinfo=UTC)
    return ts


@public_router.get("/api/public/trending")
async def trending(db: Session = Depends(get_db)):
    now = datetime.now(UTC)
    since = now - timedelta(days=30)
    rows = [r for r in db.query(ScanEvent).all() if (_as_utc(r.created_at) or now) >= since]
    total = len(rows)
    flagged_rows = [r for r in rows if r.verdict in _FLAGGED]
    brands = Counter(r.brand for r in rows if r.brand)
    domains = Counter(r.domain for r in flagged_rows if r.domain)
    patterns = Counter()
    for r in rows:
        for code in (r.finding_codes or "").split(","):
            if code and code != "clean":
                patterns[code] += 1
    last7 = sum(1 for r in rows if (_as_utc(r.created_at) or now) >= now - timedelta(days=7))
    return {
        "window_days": 30,
        "total_scans": total,
        "flagged": len(flagged_rows),
        "flagged_pct": round(100 * len(flagged_rows) / total, 1) if total else 0.0,
        "scans_last_7_days": last7,
        "top_impersonated_brands": [
            {"name": name, "count": count} for name, count in brands.most_common(5)
        ],
        "top_flagged_domains": [
            {"domain": domain, "count": count}
            for domain, count in domains.most_common(10) if count >= 2
        ][:5],
        "top_patterns": [
            {"code": code, "label": _PATTERN_LABELS.get(code, code.replace("-", " ").capitalize()), "count": count}
            for code, count in patterns.most_common(5)
        ],
    }


@router.get("/history")
async def history(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = (
        db.query(ScanHistory)
        .filter(ScanHistory.user_id == user.id)
        .order_by(ScanHistory.created_at.desc())
        .limit(50)
        .all()
    )
    return [
        {
            "id": r.id, "scan_type": r.scan_type, "target": r.target,
            "risk_score": r.risk_score, "verdict": r.verdict,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]
