"""Honeypot registration and listing with live status (FR-C2)."""
from __future__ import annotations

import secrets
import uuid

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from app.db.models import Honeypot, Profile
from app.schemas.honeypot import HoneypotCreate, HoneypotCreated, HoneypotOut
from app.security.deps import CurrentOperator, DbSession
from app.security.passwords import hash_token
from app.services import audit, orchestrator
from app.services.liveness import effective_status

router = APIRouter(prefix="/honeypots", tags=["honeypots"])


def _to_out(hp: Honeypot) -> HoneypotOut:
    out = HoneypotOut.model_validate(hp)
    out.status = effective_status(hp)
    return out


@router.get("", response_model=list[HoneypotOut])
async def list_honeypots(current: CurrentOperator, db: DbSession):
    result = await db.execute(select(Honeypot).order_by(Honeypot.created_at.desc()))
    return [_to_out(hp) for hp in result.scalars().all()]


@router.post("", response_model=HoneypotCreated, status_code=status.HTTP_201_CREATED)
async def register_honeypot(body: HoneypotCreate, current: CurrentOperator, db: DbSession):
    profile = await db.get(Profile, body.profile_id)
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="profile_id does not exist"
        )

    # Enrollment token: shown to the operator once, stored only as a hash.
    enroll_token = secrets.token_urlsafe(32)
    hp = Honeypot(
        name=body.name,
        profile_id=body.profile_id,
        host_label=body.host_label,
        enroll_token_hash=hash_token(enroll_token),
        status="unknown",
    )
    db.add(hp)
    await db.flush()
    await audit.record(
        db, operator_id=current.id, action="honeypot.register", target=str(hp.id)
    )
    await db.commit()
    await db.refresh(hp)
    return HoneypotCreated(honeypot=_to_out(hp), enroll_token=enroll_token)


@router.post("/deploy", status_code=status.HTTP_201_CREATED)
async def deploy_from_profile(body: HoneypotCreate, current: CurrentOperator, db: DbSession):
    """One-button deploy from a profile (Bonus FR-C6).

    Creates a new honeypot bound to the profile, then launches a honeypot-host
    container that self-enrolls with a fresh token. Lab-only (needs the Docker
    socket mounted into the center).
    """
    profile = await db.get(Profile, body.profile_id)
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="profile_id does not exist"
        )

    if not orchestrator.available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Orchestrator is disabled on this host (no Docker socket).",
        )

    enroll_token = secrets.token_urlsafe(32)
    hp = Honeypot(
        name=body.name,
        profile_id=body.profile_id,
        host_label=body.host_label,
        enroll_token_hash=hash_token(enroll_token),
        status="unknown",
    )
    db.add(hp)
    await db.flush()  # assign id without committing yet

    # Launch first; only persist the honeypot if the container actually started,
    # so a failed deploy never leaves an orphan record.
    try:
        container_id = await orchestrator.deploy_honeypot(str(hp.id), enroll_token)
    except Exception as exc:  # noqa: BLE001
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"deploy failed: {exc.__class__.__name__}: {exc}",
        )

    await audit.record(db, operator_id=current.id, action="honeypot.deploy", target=str(hp.id))
    await db.commit()
    await db.refresh(hp)
    return {"status": "deploying", "container_id": container_id, "honeypot": _to_out(hp)}


@router.get("/{honeypot_id}", response_model=HoneypotOut)
async def get_honeypot(honeypot_id: uuid.UUID, current: CurrentOperator, db: DbSession):
    hp = await db.get(Honeypot, honeypot_id)
    if hp is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Honeypot not found")
    return _to_out(hp)


@router.delete("/{honeypot_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_honeypot(honeypot_id: uuid.UUID, current: CurrentOperator, db: DbSession):
    hp = await db.get(Honeypot, honeypot_id)
    if hp is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Honeypot not found")
    await db.delete(hp)
    await audit.record(
        db, operator_id=current.id, action="honeypot.delete", target=str(honeypot_id)
    )
    await db.commit()
