"""Threat intel & deception surfaces (features #2 and #3)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select

from app.db.models import DeceptionAction
from app.security.deps import CurrentOperator, DbSession
from app.services import intel

router = APIRouter(tags=["intel"])


@router.get("/attackers")
async def list_attackers(
    current: CurrentOperator, db: DbSession, limit: int = Query(default=50, ge=1, le=200)
):
    return await intel.list_attackers(db, limit)


@router.get("/attackers/{source_ip}")
async def attacker_detail(source_ip: str, current: CurrentOperator, db: DbSession):
    detail = await intel.attacker_detail(db, source_ip)
    if detail is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such attacker")
    return detail


@router.get("/deception")
async def list_deception(
    current: CurrentOperator, db: DbSession, limit: int = Query(default=50, ge=1, le=200)
):
    rows = (
        await db.execute(
            select(DeceptionAction).order_by(DeceptionAction.created_at.desc()).limit(limit)
        )
    ).scalars().all()
    return [
        {
            "id": a.id,
            "action": a.action,
            "source_ip": str(a.source_ip) if a.source_ip else None,
            "honeypot_id": str(a.honeypot_id) if a.honeypot_id else None,
            "detail": a.detail,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in rows
    ]
