"""Agent-facing API (fronted by disguised /assets/v3/* in Nginx).

Routes are deliberately plain: /agent/enroll, /agent/config, /agent/telemetry.
All responses avoid honeypot/c2 wording. See docs/DESIGN.md §6.2.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from app.db.models import Artifact, Honeypot, Profile
from app.config import get_settings
from app.schemas.agent import (
    ArtifactIn,
    ClientCert,
    ConfigPayload,
    EnrollRequest,
    EnrollResponse,
    RotateResponse,
    TelemetryIn,
    TelemetryResponse,
)
from app.security import ca
from app.security.agent_auth import AgentHoneypot
from app.security.deps import DbSession
from app.security.passwords import hash_token
from app.services import alerts, commands, deception, exposure, telemetry
from app.services.config_etag import compute_etag

router = APIRouter(prefix="/agent", tags=["agent"])

settings = get_settings()
NEXT_POLL_S = 30


def _issue_mtls(agent_id: str) -> ClientCert | None:
    if not settings.mtls_enabled:
        return None
    cert_pem, key_pem, expires = ca.issue_client_cert(common_name=agent_id)
    return ClientCert(
        ca_cert=ca.ca_cert_pem(),
        client_cert=cert_pem,
        client_key=key_pem,
        cert_expires_at=expires,
    )


async def _profile_config(db: DbSession, hp: Honeypot) -> dict:
    """Effective config: the profile with the honeypot's current disguise applied
    (self-defense re-masking, feature #4). Changing the disguise changes the etag,
    so the agent refetches and re-applies its process name."""
    profile = await db.get(Profile, hp.profile_id)
    config = dict(profile.config) if profile else {}
    if hp.disguise_name:
        masking = dict(config.get("masking") or {})
        masking["process_name"] = hp.disguise_name
        config["masking"] = masking
    return config


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
        mtls=_issue_mtls(str(hp.id)),
    )


@router.post("/rotate", response_model=RotateResponse)
async def rotate_cert(hp: AgentHoneypot):
    """Issue a fresh client cert (MASK-7 rotation). Authenticated by agent key;
    the transport is already mTLS-protected by nginx on this path."""
    if not settings.mtls_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    cert_pem, key_pem, expires = ca.issue_client_cert(common_name=str(hp.id))
    return RotateResponse(
        ca_cert=ca.ca_cert_pem(),
        client_cert=cert_pem,
        client_key=key_pem,
        cert_expires_at=expires,
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
    new_alerts = await alerts.evaluate(db, redis, hp, body.events)
    await exposure.evaluate(db, redis, hp, body.events)      # feature #4
    await deception.evaluate(db, redis, new_alerts)          # feature #3
    await commands.ack(db, body.acked_commands)              # command channel
    pending = await commands.pending_for(db, hp)
    await telemetry.mark_seen(db, hp)
    await db.commit()

    config = await _profile_config(db, hp)
    return TelemetryResponse(
        accepted=accepted,
        next_poll_s=NEXT_POLL_S,
        config_etag=compute_etag(config),
        commands=pending,
    )


@router.post("/artifact")
async def upload_artifact(body: ArtifactIn, hp: AgentHoneypot, db: DbSession):
    """Receive a file captured on a honeypot (FR-A5 uploaded files): store it
    with its SHA-256 and record an artifact row."""
    try:
        data = base64.b64decode(body.content_b64)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="bad content")
    data = data[:1_000_000]  # cap at 1 MB
    sha = hashlib.sha256(data).hexdigest()
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", body.filename)[:64] or "file"
    os.makedirs(settings.artifacts_dir, exist_ok=True)
    path = os.path.join(settings.artifacts_dir, f"{sha[:12]}_{safe}")
    with open(path, "wb") as f:
        f.write(data)
    db.add(Artifact(honeypot_id=hp.id, session_id=body.session_id, kind="upload",
                    path=path, sha256=sha))
    await db.commit()
    return {"stored": True, "sha256": sha, "size": len(data)}
