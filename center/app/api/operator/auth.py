"""Operator authentication: login, refresh, me (FR-C5)."""
from __future__ import annotations

import uuid
from typing import Annotated

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select

from app.db.models import Operator
from app.schemas.auth import AccessToken, OperatorOut, RefreshRequest, TokenPair
from app.security.deps import CurrentOperator, DbSession
from app.security.jwt import create_access_token, create_refresh_token, decode_token
from app.security.passwords import verify_password
from app.services import audit

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenPair)
async def login(
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DbSession,
    request: Request,
):
    result = await db.execute(select(Operator).where(Operator.username == form.username))
    operator = result.scalar_one_or_none()
    if operator is None or not verify_password(form.password, operator.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password"
        )
    await audit.record(
        db,
        operator_id=operator.id,
        action="login",
        ip=request.client.host if request.client else None,
    )
    await db.commit()
    return TokenPair(
        access_token=create_access_token(str(operator.id), operator.role),
        refresh_token=create_refresh_token(str(operator.id)),
    )


@router.post("/refresh", response_model=AccessToken)
async def refresh(body: RefreshRequest, db: DbSession):
    try:
        payload = decode_token(body.refresh_token)
        if payload.get("type") != "refresh":
            raise ValueError("wrong token type")
        subject = payload["sub"]
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )
    operator = await db.get(Operator, uuid.UUID(subject))
    if operator is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )
    return AccessToken(access_token=create_access_token(str(operator.id), operator.role))


# Mounted at the /api/v1 root (not under /auth), per DESIGN §6.1.
me_router = APIRouter(tags=["auth"])


@me_router.get("/me", response_model=OperatorOut)
async def me(current: CurrentOperator):
    return current
