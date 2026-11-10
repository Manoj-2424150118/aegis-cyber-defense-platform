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
from app.deps import get_current_user
from app.modules import totp
from app.schemas import (
    LoginRequest,
    MfaConfirmRequest,
    MfaDisableRequest,
    MfaLoginRequest,
    MfaSetupRequest,
    RegisterRequest,
    TokenResponse,
)
from app.security import (
    create_access_token,
    create_refresh_token,
    create_token,
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
async def register(body: RegisterRequest, response: Response, db: Session = Depends(get_db)):
    from app.modules.password_lab import assess_password, breach_check

    assessment = assess_password(body.password)
    if assessment["is_common_password"] or assessment["score"] < 30:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "That password is too weak or too common. Choose a longer, unique password or passphrase.",
        )
    # Refuse passwords already known to breach corpora (k-anonymity lookup;
    # when the service is unreachable the local gates above still apply).
    breach = await breach_check(body.password)
    if breach.get("breached"):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "That password has appeared in known data breaches. Choose a unique one you have never used elsewhere.",
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
    if user.totp_enabled and user.totp_secret:
        challenge = create_token(user.email, "mfa", timedelta(minutes=5))
        return TokenResponse(mfa_required=True, challenge=challenge)
    return _issue(user, response)


@router.post("/login/mfa", response_model=TokenResponse)
def login_mfa(body: MfaLoginRequest, response: Response, db: Session = Depends(get_db)):
    email = decode_token(body.challenge, expected_type="mfa")
    if email is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign-in challenge expired. Log in again.")
    user = db.query(User).filter(User.email == email).first()
    if user is None or not user.totp_enabled or not user.totp_secret:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Two-factor sign-in is not active for this account.")
    if not totp.verify(user.totp_secret, body.code):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid authentication code.")
    return _issue(user, response)


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {
        "email": user.email,
        "plan": user.plan or "free",
        "totp_enabled": bool(user.totp_enabled),
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


@router.post("/mfa/setup")
def mfa_setup(body: MfaSetupRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid password.")
    new_secret = totp.generate_secret()
    user.totp_secret = new_secret
    user.totp_enabled = False  # activates only after a confirmed code
    db.commit()
    return {"secret": new_secret, "otpauth_uri": totp.provisioning_uri(new_secret, user.email)}


@router.post("/mfa/confirm")
def mfa_confirm(body: MfaConfirmRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user.totp_secret or not totp.verify(user.totp_secret, body.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That code did not match. Check your authenticator app and try again.")
    user.totp_enabled = True
    db.commit()
    return {"totp_enabled": True}


@router.post("/mfa/disable")
def mfa_disable(body: MfaDisableRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid password.")
    if not user.totp_secret or not totp.verify(user.totp_secret, body.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That code did not match.")
    user.totp_secret = None
    user.totp_enabled = False
    db.commit()
    return {"totp_enabled": False}


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
