"""TOTP two-factor authentication (RFC 6238) — standard library only.

Secrets are per-account random base32 strings stored on the user row
(they are server-side shared secrets by design of TOTP; account
passwords remain Argon2id-hashed and vault items remain encrypted
under the user's master password, which MFA never touches).
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

ISSUER = "Aegis"


def generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _code_at(secret: str, timestamp: float, digits: int = 6, period: int = 30) -> str:
    padding = "=" * (-len(secret) % 8)
    key = base64.b32decode(secret + padding)
    counter = int(timestamp // period)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**digits)).zfill(digits)


def verify(secret: str, code: str, window: int = 1) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return False
    now = time.time()
    return any(
        hmac.compare_digest(_code_at(secret, now + step * 30), code)
        for step in range(-window, window + 1)
    )


def provisioning_uri(secret: str, email: str) -> str:
    label = urllib.parse.quote(f"{ISSUER}:{email}")
    params = urllib.parse.urlencode({"secret": secret, "issuer": ISSUER, "digits": 6, "period": 30})
    return f"otpauth://totp/{label}?{params}"


def current_code(secret: str) -> str:
    """For tests and local verification only."""
    return _code_at(secret, time.time())
