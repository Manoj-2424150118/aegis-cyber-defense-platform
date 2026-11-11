"""Pro API keys (spec §2: API access is a Pro entitlement).

Keys are shown exactly once at creation. Only an HMAC of the key is
stored, keyed by the server secret — a database read yields nothing
usable, and keys can be revoked individually. Authentication accepts
``X-API-Key`` anywhere a bearer token is accepted, and resolves to
the owning user so every existing server-side entitlement applies.
"""

import hashlib
import hmac
import secrets
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.config import settings
from app.models import ApiKey, User

KEY_PREFIX = "agk_"
DISPLAY_PREFIX_LEN = 12


def _hash(key: str) -> str:
    return hmac.new(settings.secret_key.encode(), key.encode(), hashlib.sha256).hexdigest()


def create_key(db: Session, user: User, name: str) -> tuple[ApiKey, str]:
    plaintext = KEY_PREFIX + secrets.token_urlsafe(32)
    row = ApiKey(
        user_id=user.id,
        name=(name or "API key")[:80],
        key_prefix=plaintext[:DISPLAY_PREFIX_LEN],
        key_hash=_hash(plaintext),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row, plaintext


def user_from_api_key(db: Session, key: str | None) -> User | None:
    if not key or not key.startswith(KEY_PREFIX):
        return None
    row = (
        db.query(ApiKey)
        .filter(ApiKey.key_hash == _hash(key), ApiKey.revoked.is_(False))
        .first()
    )
    if row is None:
        return None
    row.last_used_at = datetime.now(UTC)
    db.commit()
    return db.query(User).filter(User.id == row.user_id).first()
