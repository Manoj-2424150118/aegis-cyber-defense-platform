"""Vault router — encrypted items. The server only ever stores AES-256-GCM
ciphertext keyed by the user's master password (Argon2id-derived)."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import get_current_user
from app.models import User, VaultItem
from app.modules import vault as vault_crypto
from app.schemas import VaultCreateRequest, VaultOpenRequest

router = APIRouter(prefix="/api/vault", tags=["vault"])


@router.post("", status_code=201)
def create_item(body: VaultCreateRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    salt = vault_crypto.new_salt()
    blob = vault_crypto.encrypt_item(body.master_password, salt, body.secret)
    item = VaultItem(user_id=user.id, title=body.title, ciphertext=blob)
    db.add(item)
    db.commit()
    db.refresh(item)
    return {"id": item.id, "title": item.title, "created_at": item.created_at.isoformat() if item.created_at else None}


@router.get("")
def list_items(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(VaultItem).filter(VaultItem.user_id == user.id).order_by(VaultItem.created_at.desc()).all()
    return [{"id": r.id, "title": r.title, "created_at": r.created_at.isoformat() if r.created_at else None} for r in rows]


@router.post("/{item_id}/open")
def open_item(item_id: int, body: VaultOpenRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    item = db.query(VaultItem).filter(VaultItem.id == item_id, VaultItem.user_id == user.id).first()
    if item is None:
        raise HTTPException(404, "Vault item not found.")
    try:
        secret = vault_crypto.decrypt_item(body.master_password, item.ciphertext)
    except ValueError:
        raise HTTPException(400, "Wrong master password or corrupted item.") from None
    return {"id": item.id, "title": item.title, "secret": secret}


@router.delete("/{item_id}", status_code=204)
def delete_item(item_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    item = db.query(VaultItem).filter(VaultItem.id == item_id, VaultItem.user_id == user.id).first()
    if item is None:
        raise HTTPException(404, "Vault item not found.")
    db.delete(item)
    db.commit()
    return None
