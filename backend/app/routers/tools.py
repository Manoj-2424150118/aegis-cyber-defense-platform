"""Security-tools router — the six Aegis protection modules as APIs.

Analysis endpoints work without an account (a person who just received a
suspicious link should not need to register to check it). When a user is
logged in, scans are saved to their history for the dashboard.
"""

import logging
import time as _time
from collections import Counter
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app import streaming
from app.config import settings
from app.db import SessionLocal, get_db
from app.deps import get_current_user
from app.entitlements import is_pro
from app.models import ScanEvent, ScanHistory, User
from app.modules import (
    domain_checker,
    email_analyzer,
    file_scanner,
    message_analyzer,
    password_lab,
    redirect_tracer,
    secret_scanner,
    smart_scan,
    tls_inspector,
    url_analyzer,
    web_audit,
)
from app.modules.detection import enrich_meta
from app.quota import scan_quota
from app.rate_limit import client_ip
from app.schemas import (
    DomainRequest,
    EmailRequest,
    GenerateRequest,
    MessageRequest,
    PasswordRequest,
    SecretScanRequest,
    SmartScanRequest,
    TlsRequest,
    UrlRequest,
    WebAuditRequest,
)
from app.validation import host_from_url, is_valid_domain, is_valid_host

logger = logging.getLogger("aegis.tools")

router = APIRouter(prefix="/api/tools", tags=["tools"], dependencies=[Depends(scan_quota)])


def _record(db: Session, user: User | None, scan_type: str, target: str, score: int, verdict: str) -> None:
    if user is None:
        return
    db.add(ScanHistory(user_id=user.id, scan_type=scan_type, target=target[:500], risk_score=score, verdict=verdict))
    db.commit()


def _optional_user(db: Session = Depends(get_db)):
    return None  # anonymous by default; history is recorded via /api/history for logged-in clients


_FLAGGED = ("suspicious", "malicious")

# Anti-poisoning burst cap for the public aggregate: repeats of the same
# scan signature from the same source are genuine signal (several people
# checking the same phish), so the first few count — but one source
# bulk-submitting one payload cannot inflate the public counts or push a
# fabricated domain into "top flagged". The source key is used only for
# this in-memory cap and is never stored (telemetry keeps no IPs).
_EVENT_BURST_WINDOW = 60
_EVENT_BURST_MAX = 3
_recent_events: dict[tuple, tuple[float, int]] = {}


def _over_burst_cap(key: tuple) -> bool:
    now = _time.monotonic()
    if len(_recent_events) > 4096:  # bound memory; stale entries are useless anyway
        _recent_events.clear()
    start, count = _recent_events.get(key, (now, 0))
    if now - start >= _EVENT_BURST_WINDOW:
        start, count = now, 0
    count += 1
    _recent_events[key] = (start, count)
    return count > _EVENT_BURST_MAX


def _record_event(scan_type: str, verdict: str, risk_score: int, domain: str | None = None,
                  brand: str | None = None, codes: tuple[str, ...] | list[str] = (),
                  source: str | None = None) -> None:
    """Store one privacy-safe aggregate event for the Trends view.

    The flagged domain and impersonated brand are kept only for
    suspicious/malicious verdicts — what people check on safe links is
    nobody's business. Telemetry must never break a scan, so every
    failure is swallowed.
    """
    if verdict not in _FLAGGED:
        domain, brand = None, None
    codes_key = ",".join(codes)[:500]
    # The burst cap guards only the poisonable surface (flagged
    # domains/brands); plain scan counts always record.
    if (domain or brand) and _over_burst_cap((source or "anon", scan_type, domain, brand, codes_key)):
        return
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


def _record_url_event(raw_url: str, report, source: str | None = None) -> None:
    _record_event(
        "url", report.verdict, report.risk_score,
        domain=url_analyzer.registrable_domain(raw_url),
        brand=url_analyzer.impersonated_brand(raw_url),
        codes=[f["code"] for f in report.findings],
        source=source,
    )


@router.post("/url")
async def check_url(body: UrlRequest, request: Request):
    report = url_analyzer.analyze_url(body.url)
    _record_url_event(body.url, report, source=client_ip(request))
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
    # (a multi-GB "file" must not be able to OOM the service). When the
    # client declared a Content-Length up front, reject instantly
    # instead of reading the body first.
    limit = settings.max_upload_bytes
    if file.size is not None and file.size > limit:
        raise HTTPException(413, f"File exceeds the {limit // (1024 * 1024)} MB scanning limit.")
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
async def check_email(body: EmailRequest, request: Request):
    if not body.headers.strip() and not body.body.strip():
        raise HTTPException(400, "Provide email headers, body, or both.")
    result = email_analyzer.analyze_email(body.headers, body.body)
    _record_event("email", result["verdict"], result["risk_score"],
                  domain=result.get("from_domain") or None,
                  codes=[f["code"] for f in result["findings"]],
                  source=client_ip(request))
    return result


@router.post("/web-audit")
async def audit(body: WebAuditRequest):
    try:
        # audit_website does blocking network I/O (up to its 8s timeout).
        # Run it in the threadpool: calling it inline would freeze the
        # event loop — and an audit of THIS service would deadlock
        # against itself until timeout.
        started = _time.perf_counter()
        result = await run_in_threadpool(web_audit.audit_website, body.url)
        return enrich_meta(result, "web-audit", duration_ms=int((_time.perf_counter() - started) * 1000),
                           sources_used=("http-fetch",))
    except ValueError as exc:
        # SSRF guard and scheme validation land here — a clean 400, never a 500.
        raise HTTPException(400, str(exc)) from None


@router.post("/message")
async def check_message(body: MessageRequest, request: Request):
    if not body.text.strip():
        raise HTTPException(400, "Paste a message to check.")
    result = message_analyzer.analyze_message(body.text)
    _record_event("message", result["verdict"], result["risk_score"],
                  codes=[f["code"] for f in result["findings"]],
                  source=client_ip(request))
    return result


def _checked_domain(raw: str) -> str:
    host = host_from_url(raw)
    if not is_valid_domain(host):
        # Generic on purpose: never reflect raw user input back in an
        # error body (reflected-content hygiene, even in JSON).
        raise HTTPException(400, "That doesn't look like a valid domain name.")
    return host


@router.post("/domain")
async def check_domain(body: DomainRequest):
    domain = _checked_domain(body.domain)
    # DNS lookups block; keep them off the event loop.
    started = _time.perf_counter()
    result = await run_in_threadpool(domain_checker.check_domain, domain)
    return enrich_meta(result, "domain", duration_ms=int((_time.perf_counter() - started) * 1000),
                       sources_used=("dns",))


@router.post("/tls")
async def check_tls(body: TlsRequest):
    host = host_from_url(body.host)
    if not is_valid_host(host):
        raise HTTPException(400, "That doesn't look like a valid domain name or IP address.")
    try:
        # TLS handshakes block; run in the threadpool like the audit.
        started = _time.perf_counter()
        result = await run_in_threadpool(tls_inspector.inspect_tls, host)
        return enrich_meta(result, "tls", duration_ms=int((_time.perf_counter() - started) * 1000),
                           sources_used=("tls-handshake",))
    except ValueError as exc:
        # SSRF guard (non-public hosts) — a clean 400, never a 500.
        raise HTTPException(400, str(exc)) from None


@router.post("/secret-scan")
async def secret_scan(body: SecretScanRequest, request: Request):
    """Find leaked credentials in pasted text. The text is analysed in
    memory only; the response contains masked forms exclusively —
    never the secret itself."""
    result = secret_scanner.scan_secrets(body.text)
    _record_event("secret-scan", result["verdict"], result["risk_score"],
                  codes=[f["code"] for f in result["findings"]],
                  source=client_ip(request))
    return result


@router.post("/smart-scan")
async def smart_scan_endpoint(body: SmartScanRequest, request: Request):
    """One box for anything pasted: Smart Scan detects whether the
    input is a link, an email or a message and runs the matching
    engine. The aggregate event recorded is the same one the dedicated
    tool would have recorded, so Trends stays consistent."""
    if not body.text.strip():
        raise HTTPException(400, "Paste a link, an email or a message to check.")
    envelope = smart_scan.smart_scan(body.text)
    envelope.setdefault("meta", {"schema_version": "2.0", "engine": "smart-scan",
                                 "sources_used": [envelope["detected_type"]], "degraded": False, "cached": False})
    result = envelope["result"]
    codes = [f["code"] for f in result["findings"]]
    if envelope["detected_type"] == "url":
        target = body.text.strip()
        _record_event("url", result["verdict"], result["risk_score"],
                      domain=url_analyzer.registrable_domain(target),
                      brand=url_analyzer.impersonated_brand(target), codes=codes,
                      source=client_ip(request))
    elif envelope["detected_type"] == "secret":
        _record_event("secret-scan", result["verdict"], result["risk_score"], codes=codes,
                      source=client_ip(request))
    elif envelope["detected_type"] == "email":
        _record_event("email", result["verdict"], result["risk_score"],
                      domain=result.get("from_domain") or None, codes=codes,
                      source=client_ip(request))
    else:
        _record_event("message", result["verdict"], result["risk_score"], codes=codes,
                      source=client_ip(request))
    return envelope


# ── Live-streamed analysis (Server-Sent Events) ──────────────────────
# Same engines, executed stage-by-stage so the UI can show the agent's
# work as it happens. Final event payload == classic endpoint payload.

_SSE_HEADERS = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}


@router.post("/url/stream")
async def check_url_stream(body: UrlRequest, request: Request):
    source = client_ip(request)

    async def gen():
        async for chunk in streaming.stream_url(body.url):
            yield chunk
        _record_url_event(body.url, url_analyzer.analyze_url(body.url), source=source)

    return StreamingResponse(gen(), media_type="text/event-stream", headers=_SSE_HEADERS)


@router.post("/email/stream")
async def check_email_stream(body: EmailRequest, request: Request):
    if not body.headers.strip() and not body.body.strip():
        raise HTTPException(400, "Provide email headers, body, or both.")

    source = client_ip(request)

    async def gen():
        async for chunk in streaming.stream_email(body.headers, body.body):
            yield chunk
        result = email_analyzer.analyze_email(body.headers, body.body)
        _record_event("email", result["verdict"], result["risk_score"],
                      domain=result.get("from_domain") or None,
                      codes=[f["code"] for f in result["findings"]],
                      source=source)

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
async def check_message_stream(body: MessageRequest, request: Request):
    if not body.text.strip():
        raise HTTPException(400, "Paste a message to check.")

    source = client_ip(request)

    async def gen():
        async for chunk in streaming.stream_message(body.text):
            yield chunk
        result = message_analyzer.analyze_message(body.text)
        _record_event("message", result["verdict"], result["risk_score"],
                      codes=[f["code"] for f in result["findings"]],
                      source=source)

    return StreamingResponse(gen(), media_type="text/event-stream", headers=_SSE_HEADERS)


@router.post("/domain/stream")
async def check_domain_stream(body: DomainRequest):
    domain = _checked_domain(body.domain)
    return StreamingResponse(streaming.stream_domain(domain), media_type="text/event-stream", headers=_SSE_HEADERS)


@router.post("/tls/stream")
async def check_tls_stream(body: TlsRequest):
    host = host_from_url(body.host)
    if not is_valid_host(host):
        raise HTTPException(400, "That doesn't look like a valid domain name or IP address.")
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
    "unicode-host": "Homograph domains in other alphabets",
    "mixed-script-host": "Mixed-script homograph domains",
    "embedded-credentials": "Links with passwords baked in",
    "free-host-abuse": "Phishing pages on free hosting",
    "bec-payroll": "Payroll-diversion attempts",
    "credential-form": "Login forms embedded in emails",
    "parcel-scam": "Parcel / customs-fee scams",
    "family-emergency": "Family-emergency impersonation",
    "tech-support-scam": "Tech-support scams",
    "loan-scam": "Fake instant-loan offers",
    "investment-scam": "Investment-group / tips scams",
}


def _as_utc(ts: datetime | None) -> datetime | None:
    # SQLite returns offset-naive datetimes even for timezone-aware
    # columns; stored values are UTC by construction (models._now).
    if ts is not None and ts.tzinfo is None:
        return ts.replace(tzinfo=UTC)
    return ts


_trending_cache: tuple[float, dict] | None = None


@public_router.get("/api/public/trending")
async def trending(db: Session = Depends(get_db)):
    global _trending_cache
    cached_at = _trending_cache[0] if _trending_cache else 0.0
    if _trending_cache and (_time.monotonic() - cached_at) < settings.trending_cache_seconds:
        return _trending_cache[1]
    now = datetime.now(UTC)
    since = now - timedelta(days=30)
    rows = [r for r in db.query(ScanEvent).all() if (_as_utc(r.created_at) or now) >= since]
    total = len(rows)
    flagged_rows = [r for r in rows if r.verdict in _FLAGGED]
    brands = Counter(r.brand for r in flagged_rows if r.brand)
    domains = Counter(r.domain for r in flagged_rows if r.domain)
    patterns = Counter()
    for r in rows:
        for code in (r.finding_codes or "").split(","):
            if code and code != "clean":
                patterns[code] += 1
    last7 = sum(1 for r in rows if (_as_utc(r.created_at) or now) >= now - timedelta(days=7))
    payload = {
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
    _trending_cache = (_time.monotonic(), payload)
    return payload


@router.get("/history")
async def history(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = db.query(ScanHistory).filter(ScanHistory.user_id == user.id)
    if not is_pro(user):  # free accounts keep 30 days of history
        from datetime import UTC, datetime, timedelta

        query = query.filter(ScanHistory.created_at >= datetime.now(UTC) - timedelta(days=settings.history_free_days))
    rows = query.order_by(ScanHistory.created_at.desc()).limit(50).all()
    return [
        {
            "id": r.id, "scan_type": r.scan_type, "target": r.target,
            "risk_score": r.risk_score, "verdict": r.verdict,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]
