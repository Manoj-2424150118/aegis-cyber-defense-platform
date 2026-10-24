"""Request/response schemas — every input is validated by Pydantic before
it reaches a module (OWASP: never trust, always validate)."""

from pydantic import BaseModel, EmailStr, Field, field_validator


def _reject_whitespace(value: str) -> str:
    """URLs with embedded whitespace/control characters are never
    legitimate lookup targets — they are a classic filter-evasion and
    header-smuggling shape, so reject them at the schema boundary.
    (Format scoring of otherwise-plausible malformed URLs stays with
    the analyser engines, which return findings instead of errors.)"""
    if any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise ValueError("URL must not contain whitespace or control characters.")
    return value


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UrlRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)

    _clean_url = field_validator("url")(_reject_whitespace)


class PasswordRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class GenerateRequest(BaseModel):
    length: int = Field(default=20, ge=12, le=128)
    symbols: bool = True


class EmailRequest(BaseModel):
    headers: str = Field(default="", max_length=20000)
    body: str = Field(default="", max_length=50000)


class WebAuditRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)

    _clean_url = field_validator("url")(_reject_whitespace)


class VaultCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    secret: str = Field(min_length=1, max_length=10000)
    master_password: str = Field(min_length=12, max_length=128)


class VaultOpenRequest(BaseModel):
    master_password: str = Field(min_length=1, max_length=128)
