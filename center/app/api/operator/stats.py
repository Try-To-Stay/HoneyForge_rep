"""Lightweight aggregates for the dashboard header."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter
from sqlalchemy import func, select

from app.db.models import Event
from app.security.deps import CurrentOperator, DbSession
from app.services import orchestrator

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("/capabilities")
async def capabilities(current: CurrentOperator):
    """Which optional features are available on this deployment."""
    return {"orchestrator": orchestrator.available()}


@router.get("/summary")
async def summary(current: CurrentOperator, db: DbSession):
    total = (await db.execute(select(func.count(Event.id)))).scalar_one()

    by_type_rows = (
        await db.execute(
            select(Event.event_type, func.count(Event.id)).group_by(Event.event_type)
        )
    ).all()

    top_src_rows = (
        await db.execute(
            select(Event.source_ip, func.count(Event.id).label("c"))
            .where(Event.source_ip.is_not(None))
            .group_by(Event.source_ip)
            .order_by(func.count(Event.id).desc())
            .limit(5)
        )
    ).all()

    # Events per hour over the last 24h (for the timeline chart).
    bucket = func.date_trunc("hour", Event.occurred_at)
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    tl_rows = (
        await db.execute(
            select(bucket.label("b"), func.count(Event.id))
            .where(Event.occurred_at >= since)
            .group_by("b")
            .order_by("b")
        )
    ).all()

    top_country_rows = (
        await db.execute(
            select(Event.source_country, func.count(Event.id))
            .where(Event.source_country.is_not(None))
            .group_by(Event.source_country)
            .order_by(func.count(Event.id).desc())
            .limit(6)
        )
    ).all()

    return {
        "total_events": total,
        "by_type": {t: c for t, c in by_type_rows},
        "top_sources": [{"source_ip": str(ip), "count": c} for ip, c in top_src_rows],
        "top_countries": [{"country": c, "count": n} for c, n in top_country_rows],
        "timeline": [{"t": b.isoformat(), "count": n} for b, n in tl_rows],
    }
