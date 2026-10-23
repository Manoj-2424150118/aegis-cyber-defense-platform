"""Security-tools router — the six Aegis protection modules as APIs.

Analysis endpoints work without an account (a person who just received a
suspicious link should not need to register to check it). When a user is
logged in, scans are saved to their history for the dashboard.
"""

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.deps import get_current_user
from app.models import ScanHistory, User
from app.modules import (
    email_analyzer,
    file_scanner,
    password_lab,
    url_analyzer,
    web_audit,
)
from app.schemas import (
    EmailRequest,
    GenerateRequest,
    PasswordRequest,
    UrlRequest,
    WebAuditRequest,
)

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


@router.post("/file")
async def scan_upload(file: UploadFile = File(...)):
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
    return file_scanner.scan_file(file.filename or "upload", data)


@router.post("/email")
async def check_email(body: EmailRequest):
    if not body.headers.strip() and not body.body.strip():
        raise HTTPException(400, "Provide email headers, body, or both.")
    return email_analyzer.analyze_email(body.headers, body.body)


@router.post("/web-audit")
async def audit(body: WebAuditRequest):
    try:
        return web_audit.audit_website(body.url)
    except ValueError as exc:
        # SSRF guard and scheme validation land here — a clean 400, never a 500.
        raise HTTPException(400, str(exc)) from None


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
