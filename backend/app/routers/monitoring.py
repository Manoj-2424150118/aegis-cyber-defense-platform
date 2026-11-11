"""Domain monitoring (spec §2): free accounts watch 1 domain, Pro 10.

A "check" re-runs the public Domain Security Checker and records the
grade; if the grade moved since the last check the row is flagged so
the dashboard can show the change. There is deliberately no outbound
email/push alerting here — no mail infrastructure exists in this
service, and inventing one is an owner decision.
"""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import get_current_user
from app.entitlements import monitor_limit
from app.models import MonitoredDomain, User
from app.modules import domain_checker
from app.validation import host_from_url, is_valid_domain

router = APIRouter(prefix="/api/monitoring", tags=["monitoring"])


class MonitorCreateRequest(BaseModel):
    domain: str


def _serialise(row: MonitoredDomain) -> dict:
    return {
        "id": row.id,
        "domain": row.domain,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "last_checked_at": row.last_checked_at.isoformat() if row.last_checked_at else None,
        "last_grade": row.last_grade,
        "last_score": row.last_score,
        "change_detected": row.change_detected,
    }


def _owned(db: Session, user: User, monitor_id: int) -> MonitoredDomain:
    row = db.query(MonitoredDomain).filter(
        MonitoredDomain.id == monitor_id, MonitoredDomain.user_id == user.id
    ).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such monitored domain.")
    return row


@router.post("", status_code=status.HTTP_201_CREATED)
async def add_monitor(body: MonitorCreateRequest, user: User = Depends(get_current_user),
                      db: Session = Depends(get_db)):
    host = host_from_url(body.domain.strip())
    if not is_valid_domain(host):
        raise HTTPException(400, "That doesn't look like a valid domain name.")
    existing = db.query(MonitoredDomain).filter(
        MonitoredDomain.user_id == user.id, MonitoredDomain.domain == host
    ).first()
    if existing is not None:
        return _serialise(existing)
    limit = monitor_limit(user)
    count = db.query(MonitoredDomain).filter(MonitoredDomain.user_id == user.id).count()
    if count >= limit:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"Your plan watches up to {limit} domain{'s' if limit != 1 else ''}. "
            "Pro raises the limit to 10 with change alerts.",
        )
    row = MonitoredDomain(user_id=user.id, domain=host)
    db.add(row)
    db.commit()
    db.refresh(row)
    return _serialise(row)


@router.get("")
async def list_monitors(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(MonitoredDomain).filter(MonitoredDomain.user_id == user.id).all()
    return [_serialise(r) for r in rows]


@router.delete("/{monitor_id}")
async def delete_monitor(monitor_id: int, user: User = Depends(get_current_user),
                         db: Session = Depends(get_db)):
    row = _owned(db, user, monitor_id)
    db.delete(row)
    db.commit()
    return {"deleted": True, "id": monitor_id}


@router.post("/{monitor_id}/check")
async def check_monitor(monitor_id: int, user: User = Depends(get_current_user),
                        db: Session = Depends(get_db)):
    row = _owned(db, user, monitor_id)
    result = await run_in_threadpool(domain_checker.check_domain, row.domain)
    grade, score = result.get("grade"), result.get("score")
    row.change_detected = row.last_grade is not None and grade != row.last_grade
    row.last_grade, row.last_score = grade, score
    row.last_checked_at = datetime.now(UTC)
    db.commit()
    return {**_serialise(row), "findings": result.get("findings", [])}
