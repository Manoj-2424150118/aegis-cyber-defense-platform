"""Auth router — register / login / refresh with Argon2id + lockout.

After 5 failed logins the account locks for 15 minutes (OWASP cheat-sheet
guidance), which blunts credential-stuffing and brute-force attacks.
Generic error messages avoid revealing whether an email is registered.
"""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.config import settings
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


# The browser client never persists a token in web storage (an XSS would
# be able to read localStorage). The refresh token travels as an
# HttpOnly, SameSite=Strict cookie scoped to /api/auth; the short-lived
# access token lives only in page memory. Non-browser API clients may
# still use the refresh_token field in the JSON body.
REFRESH_COOKIE = "aegis_refresh"


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        REFRESH_COOKIE,
        token,
        max_age=settings.refresh_token_days * 24 * 3600,
        path="/api/auth",
        httponly=True,
        secure=settings.environment == "production",
        samesite="strict",
    )


def _issue(user: User, response: Response) -> TokenResponse:
    tokens = _tokens(user)
    _set_refresh_cookie(response, tokens.refresh_token)
    return tokens


@router.post("/register", response_model=TokenResponse, status_code=201)
def register(body: RegisterRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    from app.rate_limit import client_ip, register_limiter

    # F-07: hourly per-IP creation budget, checked before any other work
    # (including the password assessment and the duplicate-email query,
    # so the endpoint's cost and its enumeration surface stay minimal
    # once the budget is spent). client_ip() is the F-02-hardened
    # resolver, so the budget cannot be dodged by rotating XFF entries.
    if not register_limiter.allow(f"register:{client_ip(request)}"):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many accounts created from this connection. Try again in an hour.",
        )
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
    return _issue(user, response)


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, response: Response, db: Session = Depends(get_db)):
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
    return _issue(user, response)


@router.post("/refresh", response_model=TokenResponse)
def refresh(body: dict, request: Request, response: Response, db: Session = Depends(get_db)):
    cookie_token = request.cookies.get(REFRESH_COOKIE)
    if cookie_token:
        # Cookie-based refresh is for the first-party web client only.
        # Requiring a custom header means a cross-site form/fetch cannot
        # trigger it (custom headers force a CORS preflight), which —
        # together with SameSite=Strict — closes the CSRF angle.
        if request.headers.get("x-aegis-refresh") != "1":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token.")
        token = cookie_token
    else:
        token = body.get("refresh_token", "")
    email = decode_token(token, expected_type="refresh")
    if email is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token.")
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account no longer exists.")
    return _issue(user, response)


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(REFRESH_COOKIE, path="/api/auth")
    return {"detail": "Logged out."}
