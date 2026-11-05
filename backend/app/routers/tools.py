"""Security-tools router — the six Aegis protection modules as APIs.

Analysis endpoints work without an account (a person who just received a
suspicious link should not need to register to check it). When a user is
logged in, scans are saved to their history for the dashboard.
"""

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app import streaming
from app.config import settings
from app.db import get_db
from app.deps import get_current_user
from app.models import ScanHistory, User
from app.modules import (
    domain_checker,
    email_analyzer,
    file_scanner,
    message_analyzer,
    password_lab,
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

router = APIRouter(prefix="/api/tools", tags=["tools"])


def _record(db: Session, user: User | None, scan_type: str, target: str, score: int, verdict: str) -> None:
    if user is None:
        return
    db.add(ScanHistory(user_id=user.id, scan_type=scan_type, target=target[:500], risk_score=score, verdict=verdict))
    db.commit()


def _optional_user(db: Session = Depends(get_db)):
    return None  # anonymous by default; history is recorded via /api/history for logged-in clients


@router.post("/url")
async def check_url(body: UrlRequest):
    report = url_analyzer.analyze_url(body.url)
    return report.as_dict()


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
    return email_analyzer.analyze_email(body.headers, body.body)


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
    return message_analyzer.analyze_message(body.text)


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
    return StreamingResponse(streaming.stream_url(body.url), media_type="text/event-stream", headers=_SSE_HEADERS)


@router.post("/email/stream")
async def check_email_stream(body: EmailRequest):
    if not body.headers.strip() and not body.body.strip():
        raise HTTPException(400, "Provide email headers, body, or both.")
    return StreamingResponse(streaming.stream_email(body.headers, body.body), media_type="text/event-stream", headers=_SSE_HEADERS)


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
    return StreamingResponse(streaming.stream_message(body.text), media_type="text/event-stream", headers=_SSE_HEADERS)


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
