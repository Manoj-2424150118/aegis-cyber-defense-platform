"""Freemium scan quotas (docs/FREEMIUM.md).

Counters are keyed by an HMAC of the caller identity — a user id for
signed-in calls, or the edge IP (CF-Connecting-IP, else the rate
limiter's client IP) mixed with the day for anonymous calls. Raw IPs
are never stored; rows self-prune after 48 hours. Pro plans are
unlimited. Limits live in settings so operations can tune them without
a code change.
"""

import hashlib
import hmac
from datetime import UTC, datetime, timedelta

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.entitlements import is_pro
from app.models import ScanQuota, User
from app.rate_limit import client_ip
from app.security import decode_token


def _day(offset: int = 0) -> str:
    return (datetime.now(UTC).date() - timedelta(days=offset)).isoformat()


def _key(request: Request, user: User | None) -> str:
    if user is not None:
        raw = f"user:{user.id}"
    else:
        edge_ip = request.headers.get("cf-connecting-ip") or client_ip(request)
        raw = f"ip:{edge_ip}:{_day()}"
    return hmac.new(settings.secret_key.encode(), raw.encode(), hashlib.sha256).hexdigest()


def _optional_user(request: Request, db: Session) -> User | None:
    api_key = request.headers.get("x-api-key")
    if api_key:
        from app.apikeys import user_from_api_key

        return user_from_api_key(db, api_key)
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    email = decode_token(auth[7:].strip(), expected_type="access")
    if not email:
        return None
    return db.query(User).filter(User.email == email).first()


def scan_quota(request: Request, db: Session = Depends(get_db)) -> None:
    """Router-level dependency: count POST /api/tools/* calls (history
    bookkeeping excluded) against the caller's daily tier limit."""
    if request.method != "POST" or request.url.path == "/api/tools/history":
        return
    user = _optional_user(request, db)
    if user is not None and is_pro(user):
        return
    limit = settings.account_daily_scan_limit if user is not None else settings.anon_daily_scan_limit
    key = _key(request, user)
    row = db.query(ScanQuota).filter(ScanQuota.key_hash == key, ScanQuota.day == _day()).first()
    if row is None:
        row = ScanQuota(key_hash=key, day=_day(), count=0)
        db.add(row)
    if row.count >= limit:
        db.commit()
        if user is None:
            detail = (
                f"Daily free limit reached ({limit} checks/day without an account). "
                "Create a free account for a higher daily limit and saved history."
            )
        else:
            detail = f"Daily limit reached ({limit} checks/day on the free account plan)."
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail)
    row.count += 1
    if row.id is None or row.count % 25 == 0:  # opportunistic prune of stale rows
        db.query(ScanQuota).filter(ScanQuota.day < _day(offset=2)).delete()
    db.commit()
