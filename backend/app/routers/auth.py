"""Auth router — register / login / refresh with Argon2id + lockout.

After 5 failed logins the account locks for 15 minutes (OWASP cheat-sheet
guidance), which blunts credential-stuffing and brute-force attacks.
Generic error messages avoid revealing whether an email is registered.
"""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import User
from app.schemas import LoginRequest, RegisterRequest, TokenResponse
from app.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    is_locked,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])
MAX_FAILURES = 5
LOCK_MINUTES = 15

# Precomputed Argon2id hash of a random throwaway password. Login attempts
# for non-existent accounts verify against this so response timing does not
# reveal whether an email is registered (user-enumeration via timing).
_DUMMY_HASH = hash_password("timing-equaliser-not-a-real-password")


def _tokens(user: User) -> TokenResponse:
    return TokenResponse(
        access_token=create_access_token(user.email),
        refresh_token=create_refresh_token(user.email),
    )


@router.post("/register", response_model=TokenResponse, status_code=201)
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    from app.modules.password_lab import assess_password

    assessment = assess_password(body.password)
    if assessment["is_common_password"] or assessment["score"] < 30:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "That password is too weak or too common. Choose a longer, unique password or passphrase.",
        )
    existing = db.query(User).filter(User.email == body.email.lower()).first()
    if existing:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Registration failed. Try logging in instead.")
    user = User(email=body.email.lower(), password_hash=hash_password(body.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return _tokens(user)


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    from app.rate_limit import account_limiter

    if not account_limiter.allow(f"login:{body.email.lower()}"):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many login attempts for this account. Try again in a minute.")
    user = db.query(User).filter(User.email == body.email.lower()).first()
    if user is not None and is_locked(user):
        raise HTTPException(status.HTTP_423_LOCKED, "Account temporarily locked after repeated failed logins. Try again later.")
    if user is None:
        verify_password(body.password, _DUMMY_HASH)  # equalise timing; result discarded
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password.")
    if not verify_password(body.password, user.password_hash):
        if user is not None:
            user.failed_logins = (user.failed_logins or 0) + 1
            if user.failed_logins >= MAX_FAILURES:
                user.locked_until = datetime.now(UTC) + timedelta(minutes=LOCK_MINUTES)
                user.failed_logins = 0
            db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password.")
    user.failed_logins = 0
    user.locked_until = None
    db.commit()
    return _tokens(user)


@router.post("/refresh", response_model=TokenResponse)
def refresh(body: dict, db: Session = Depends(get_db)):
    token = body.get("refresh_token", "")
    email = decode_token(token, expected_type="refresh")
    if email is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token.")
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account no longer exists.")
    return _tokens(user)
