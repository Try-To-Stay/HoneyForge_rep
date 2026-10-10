"""JWT issuing/verification for operator auth."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt

from app.config import get_settings

settings = get_settings()
_ALG = "HS256"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(subject: str, role: str) -> str:
    exp = _now() + timedelta(minutes=settings.jwt_access_ttl_min)
    payload = {"sub": subject, "role": role, "type": "access", "exp": exp, "iat": _now()}
    return jwt.encode(payload, settings.jwt_secret, algorithm=_ALG)


def create_refresh_token(subject: str) -> str:
    exp = _now() + timedelta(days=settings.jwt_refresh_ttl_days)
    payload = {"sub": subject, "type": "refresh", "exp": exp, "iat": _now()}
    return jwt.encode(payload, settings.jwt_secret, algorithm=_ALG)


def decode_token(token: str) -> dict:
    """Decode & verify. Raises jwt.PyJWTError on invalid/expired tokens."""
    return jwt.decode(token, settings.jwt_secret, algorithms=[_ALG])
