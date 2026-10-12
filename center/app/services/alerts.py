"""Threshold alert rules (Bonus FR-C7).

Evaluated after each telemetry batch. Two rules:
- brute_force: too many login attempts from one source in a time window.
- honeytoken: any token_trigger event fires immediately.
Alerts are de-duplicated per (honeypot, source, rule) within the window and
pushed to the realtime channel so the dashboard can surface them.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.models import Alert, Event, Honeypot
from app.schemas.agent import EventIn
from app.services.telemetry import CHANNEL_ALL

settings = get_settings()


async def _recent_alert_exists(db: AsyncSession, hp_id, source_ip, rule, window_start) -> bool:
    q = select(Alert.id).where(
        Alert.honeypot_id == hp_id,
        Alert.rule == rule,
        Alert.created_at >= window_start,
    )
    if source_ip is not None:
        q = q.where(Alert.source_ip == source_ip)
    return (await db.execute(q)).first() is not None


async def _publish(redis, alert: Alert) -> None:
    if redis is None:
        return
    msg = json.dumps(
        {
            "type": "alert",
            "data": {
                "id": alert.id,
                "honeypot_id": str(alert.honeypot_id) if alert.honeypot_id else None,
                "source_ip": alert.source_ip,
                "rule": alert.rule,
                "severity": alert.severity,
                "message": alert.message,
                "event_count": alert.event_count,
                "created_at": alert.created_at.isoformat() if alert.created_at else None,
            },
        },
        default=str,
    )
    try:
        await redis.publish(CHANNEL_ALL, msg)
    except Exception:  # noqa: BLE001
        pass


async def evaluate(db: AsyncSession, redis, hp: Honeypot, events: list[EventIn]) -> list[Alert]:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=settings.alert_window_s)
    created: list[Alert] = []

    # honeytoken: fire on every token_trigger.
    for ev in events:
        if ev.event_type == "token_trigger":
            alert = Alert(
                honeypot_id=hp.id,
                source_ip=ev.source_ip,
                rule="honeytoken",
                severity="high",
                message=f"Honeytoken triggered: {ev.payload.get('token', 'canary')}",
                event_count=1,
            )
            db.add(alert)
            created.append(alert)

    # brute_force: count recent auth attempts per source.
    sources = {ev.source_ip for ev in events if ev.event_type == "auth_attempt" and ev.source_ip}
    for src in sources:
        count = (
            await db.execute(
                select(func.count(Event.id)).where(
                    Event.honeypot_id == hp.id,
                    Event.event_type == "auth_attempt",
                    Event.source_ip == src,
                    Event.occurred_at >= window_start,
                )
            )
        ).scalar_one()
        if count >= settings.alert_bruteforce_threshold and not await _recent_alert_exists(
            db, hp.id, src, "brute_force", window_start
        ):
            alert = Alert(
                honeypot_id=hp.id,
                source_ip=src,
                rule="brute_force",
                severity="high",
                message=f"{count} login attempts from {src} in {settings.alert_window_s}s",
                event_count=count,
            )
            db.add(alert)
            created.append(alert)

    if created:
        await db.flush()
        for alert in created:
            await _publish(redis, alert)
    return created
