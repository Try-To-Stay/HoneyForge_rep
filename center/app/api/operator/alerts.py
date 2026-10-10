"""Alert listing (Bonus FR-C7)."""
from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Query
from pydantic import BaseModel, field_validator
from sqlalchemy import select

from app.db.models import Alert
from app.security.deps import CurrentOperator, DbSession

router = APIRouter(prefix="/alerts", tags=["alerts"])


class AlertOut(BaseModel):
    id: int
    honeypot_id: uuid.UUID | None
    source_ip: str | None
    rule: str
    severity: str
    message: str
    event_count: int
    created_at: datetime

    model_config = {"from_attributes": True}

    @field_validator("source_ip", mode="before")
    @classmethod
    def _ip_to_str(cls, v):
        return str(v) if v is not None else None


@router.get("", response_model=list[AlertOut])
async def list_alerts(
    current: CurrentOperator, db: DbSession, limit: int = Query(default=100, ge=1, le=500)
):
    rows = (
        await db.execute(select(Alert).order_by(Alert.created_at.desc()).limit(limit))
    ).scalars().all()
    return [AlertOut.model_validate(a) for a in rows]
