"""API key management (spec §2). Creation is Pro-only — the plan gate
is enforced here on the server, never by hiding a button."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import apikeys
from app.db import get_db
from app.deps import get_current_user
from app.entitlements import is_pro
from app.models import ApiKey, User

router = APIRouter(prefix="/api/keys", tags=["api-keys"])


class KeyCreateRequest(BaseModel):
    name: str = "API key"


def _serialise(row: ApiKey) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "key_prefix": row.key_prefix,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "last_used_at": row.last_used_at.isoformat() if row.last_used_at else None,
        "revoked": row.revoked,
    }


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_key(body: KeyCreateRequest, user: User = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    if not is_pro(user):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "API access is a Pro feature. Your plan does not include API keys.")
    row, plaintext = apikeys.create_key(db, user, body.name)
    # The plaintext is returned once, in this response only.
    return {**_serialise(row), "key": plaintext}


@router.get("")
async def list_keys(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(ApiKey).filter(ApiKey.user_id == user.id).order_by(ApiKey.id.desc()).all()
    return [_serialise(r) for r in rows]


@router.delete("/{key_id}")
async def revoke_key(key_id: int, user: User = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    row = db.query(ApiKey).filter(ApiKey.id == key_id, ApiKey.user_id == user.id).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No such API key.")
    row.revoked = True
    db.commit()
    return {"revoked": True, "id": row.id}
