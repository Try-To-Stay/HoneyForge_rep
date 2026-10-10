"""Attack event querying with filters (FR-C4)."""
from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Query
from sqlalchemy import select

from app.db.models import Event
from app.schemas.event import EventOut, EventPage
from app.security.deps import CurrentOperator, DbSession

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=EventPage)
async def list_events(
    current: CurrentOperator,
    db: DbSession,
    honeypot_id: uuid.UUID | None = None,
    type: str | None = Query(default=None, alias="type"),
    source_ip: str | None = None,
    since: datetime | None = Query(default=None, alias="from"),
    until: datetime | None = Query(default=None, alias="to"),
    limit: int = Query(default=100, ge=1, le=500),
    cursor: int | None = Query(default=None, description="return events with id < cursor"),
):
    stmt = select(Event)
    if honeypot_id is not None:
        stmt = stmt.where(Event.honeypot_id == honeypot_id)
    if type is not None:
        stmt = stmt.where(Event.event_type == type)
    if source_ip is not None:
        stmt = stmt.where(Event.source_ip == source_ip)
    if since is not None:
        stmt = stmt.where(Event.occurred_at >= since)
    if until is not None:
        stmt = stmt.where(Event.occurred_at <= until)
    if cursor is not None:
        stmt = stmt.where(Event.id < cursor)

    # Keyset pagination by id desc (newest first); fetch one extra to know if more.
    stmt = stmt.order_by(Event.id.desc()).limit(limit + 1)
    rows = list((await db.execute(stmt)).scalars().all())

    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        next_cursor = rows[-1].id

    return EventPage(items=[EventOut.model_validate(r) for r in rows], next_cursor=next_cursor)
