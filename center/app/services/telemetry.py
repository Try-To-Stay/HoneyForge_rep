"""Telemetry ingestion: normalize agent events, persist idempotently, publish."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Event, Honeypot
from app.schemas.agent import EventIn

# Redis channels consumed by the realtime layer (Sprint 3).
CHANNEL_ALL = "events:all"


def _channel_for(honeypot_id) -> str:
    return f"events:{honeypot_id}"


async def mark_seen(db: AsyncSession, hp: Honeypot) -> None:
    hp.last_seen_at = datetime.now(timezone.utc)
    hp.status = "online"


async def ingest_events(
    db: AsyncSession,
    redis,
    hp: Honeypot,
    events: list[EventIn],
) -> int:
    """Persist events, skipping duplicates by dedup_key. Returns count accepted."""
    accepted = 0
    for ev in events:
        if ev.dedup_key:
            exists = await db.execute(
                select(Event.id).where(Event.dedup_key == ev.dedup_key)
            )
            if exists.scalar_one_or_none() is not None:
                continue  # already stored (buffered re-delivery, FR-A4)

        occurred = ev.occurred_at
        if occurred.tzinfo is None:
            occurred = occurred.replace(tzinfo=timezone.utc)

        row = Event(
            honeypot_id=hp.id,
            event_type=ev.event_type,
            source_ip=ev.source_ip,
            source_port=ev.source_port,
            dest_port=ev.dest_port,
            protocol=ev.protocol,
            severity=ev.severity,
            session_id=ev.session_id,
            payload=ev.payload,
            occurred_at=occurred,
            dedup_key=ev.dedup_key,
        )
        db.add(row)
        await db.flush()
        accepted += 1

        if redis is not None:
            message = json.dumps(
                {
                    "type": "event",
                    "data": {
                        "id": row.id,
                        "honeypot_id": str(hp.id),
                        "event_type": row.event_type,
                        "source_ip": row.source_ip,
                        "source_port": row.source_port,
                        "dest_port": row.dest_port,
                        "protocol": row.protocol,
                        "severity": row.severity,
                        "payload": row.payload,
                        "occurred_at": occurred.isoformat(),
                    },
                },
                default=str,
            )
            try:
                await redis.publish(_channel_for(hp.id), message)
                await redis.publish(CHANNEL_ALL, message)
            except Exception:  # noqa: BLE001 - realtime is best-effort
                pass

    return accepted
