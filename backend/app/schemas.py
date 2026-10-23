"""Request/response schemas — every input is validated by Pydantic before
it reaches a module (OWASP: never trust, always validate)."""

from pydantic import BaseModel, EmailStr, Field


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


class VaultCreateRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    secret: str = Field(min_length=1, max_length=10000)
    master_password: str = Field(min_length=12, max_length=128)


class VaultOpenRequest(BaseModel):
    master_password: str = Field(min_length=1, max_length=128)
