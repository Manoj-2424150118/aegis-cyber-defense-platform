"""Encrypted vault — zero-knowledge by design.

A random per-user data key encrypts items with AES-256-GCM (authenticated
encryption). The data key itself is wrapped with a key derived from the
user's master password via Argon2id — the server stores only ciphertext,
so a database leak reveals nothing usable. For this portfolio build the
wrapped key is kept in memory per session login flow via the API layer;
the crypto primitives here are the production-shaped part and are unit
tested for round-trip, tamper-detection and wrong-password failure.
"""

import base64
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_SALT_BYTES = 16
_KEY_BYTES = 32  # AES-256


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text.encode())


def derive_key(master_password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=64 * 1024,
        parallelism=2,
        hash_len=_KEY_BYTES,
        type=Type.ID,
    )


def new_salt() -> bytes:
    return os.urandom(_SALT_BYTES)


def encrypt_item(master_password: str, salt: bytes, plaintext: str) -> str:
    """Return base64(salt || nonce || ciphertext+tag)."""
    key = derive_key(master_password, salt)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return _b64(salt + nonce + ciphertext)


def decrypt_item(master_password: str, blob: str) -> str:
    """Decrypt a blob produced by :func:`encrypt_item`.

    Raises ValueError on a wrong password or any tampering — GCM's
    authentication tag makes silent corruption impossible.
    """
    try:
        raw = _unb64(blob)
        salt, nonce, ciphertext = raw[:_SALT_BYTES], raw[_SALT_BYTES:_SALT_BYTES + 12], raw[_SALT_BYTES + 12:]
        key = derive_key(master_password, salt)
        return AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8")
    except (InvalidTag, ValueError, IndexError) as exc:
        raise ValueError("Decryption failed: wrong master password or corrupted data.") from exc


def encrypt_with_key(key: bytes, plaintext: str) -> str:
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return _b64(nonce + ciphertext)


def decrypt_with_key(key: bytes, blob: str) -> str:
    try:
        raw = _unb64(blob)
        return AESGCM(key).decrypt(raw[:12], raw[12:], None).decode("utf-8")
    except (InvalidTag, ValueError, IndexError) as exc:
        raise ValueError("Decryption failed: wrong key or corrupted data.") from exc
