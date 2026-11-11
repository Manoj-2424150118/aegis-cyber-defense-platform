"""Shared FastAPI dependencies."""

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import User
from app.security import decode_token

_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    x_api_key: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> User:
    if creds is None and x_api_key:
        # Pro API keys authenticate as their owner (app/apikeys.py).
        from app.apikeys import user_from_api_key

        user = user_from_api_key(db, x_api_key)
        if user is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or revoked API key.")
        return user
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required.")
    email = decode_token(creds.credentials)
    if email is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token.")
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account no longer exists.")
    return user
