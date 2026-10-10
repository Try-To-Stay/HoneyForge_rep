"""Agent-facing API (fronted by disguised /assets/v3/* in Nginx).

Routes are deliberately plain: /agent/enroll, /agent/config, /agent/telemetry.
All responses avoid honeypot/c2 wording. See docs/DESIGN.md §6.2.
"""
from __future__ import annotations

import secrets

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from app.db.models import Honeypot, Profile
from app.schemas.agent import (
    ConfigPayload,
    EnrollRequest,
    EnrollResponse,
    TelemetryIn,
    TelemetryResponse,
)
from app.security.agent_auth import AgentHoneypot
from app.security.deps import DbSession
from app.security.passwords import hash_token
from app.services import telemetry
from app.services.config_etag import compute_etag

router = APIRouter(prefix="/agent", tags=["agent"])

NEXT_POLL_S = 30


async def _profile_config(db: DbSession, hp: Honeypot) -> dict:
    profile = await db.get(Profile, hp.profile_id)
    return profile.config if profile else {}


@router.post("/enroll", response_model=EnrollResponse)
async def enroll(body: EnrollRequest, db: DbSession):
    token_hash = hash_token(body.enroll_token)
    result = await db.execute(
        select(Honeypot).where(Honeypot.enroll_token_hash == token_hash)
    )
    hp = result.scalar_one_or_none()
    if hp is None:
        # Plausible "not found" rather than a 401 that would flag enrollment.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")

    agent_key = secrets.token_urlsafe(32)
    hp.agent_key_hash = hash_token(agent_key)
    await telemetry.mark_seen(db, hp)
    await db.commit()

    config = await _profile_config(db, hp)
    return EnrollResponse(
        agent_id=hp.id,
        agent_key=agent_key,
        config=config,
        config_etag=compute_etag(config),
    )


@router.get("/config", response_model=ConfigPayload)
async def get_config(hp: AgentHoneypot, db: DbSession):
    config = await _profile_config(db, hp)
    await telemetry.mark_seen(db, hp)
    await db.commit()
    return ConfigPayload(config=config, config_etag=compute_etag(config))


@router.post("/telemetry", response_model=TelemetryResponse)
async def post_telemetry(body: TelemetryIn, hp: AgentHoneypot, db: DbSession, request: Request):
    redis = getattr(request.app.state, "redis", None)
    accepted = await telemetry.ingest_events(db, redis, hp, body.events)
    await telemetry.mark_seen(db, hp)
    await db.commit()

    config = await _profile_config(db, hp)
    return TelemetryResponse(
        accepted=accepted,
        next_poll_s=NEXT_POLL_S,
        config_etag=compute_etag(config),
    )
