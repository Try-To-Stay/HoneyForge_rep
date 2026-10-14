"""FastAPI dependencies: DB session and current authenticated operator."""
from __future__ import annotations

import uuid
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import SessionLocal
from app.db.models import Operator
from app.security.jwt import decode_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=True)


async def get_db() -> AsyncSession:
    async with SessionLocal() as session:
        yield session


DbSession = Annotated[AsyncSession, Depends(get_db)]


async def get_current_operator(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: DbSession,
) -> Operator:
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            raise cred_exc
        subject = payload.get("sub")
        if not subject:
            raise cred_exc
    except jwt.PyJWTError:
        raise cred_exc

    operator = await db.get(Operator, uuid.UUID(subject))
    if operator is None:
        raise cred_exc
    return operator


CurrentOperator = Annotated[Operator, Depends(get_current_operator)]


async def get_current_admin(current: CurrentOperator) -> Operator:
    """Require the admin role for mutating actions (RBAC, FR-C5)."""
    if current.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires the admin role",
        )
    return current


CurrentAdmin = Annotated[Operator, Depends(get_current_admin)]
