"""Password and secret hashing (Argon2)."""
from __future__ import annotations

import hashlib

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_ph = PasswordHasher()


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except Exception:  # noqa: BLE001 - malformed hash etc.
        return False


def hash_token(token: str) -> str:
    """Deterministic hash for opaque tokens (enrollment / agent keys).

    Unlike passwords these are looked up by value, so we need a stable digest
    rather than a salted Argon2 hash.
    """
    return hashlib.sha256(token.encode()).hexdigest()
