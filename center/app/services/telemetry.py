"""Telemetry ingestion: normalize agent events, persist idempotently, publish.

Beyond raw events, Medium-honeypot telemetry also materializes session and
auth-attempt rows. Passwords are never stored in clear: auth_attempts keep a
hash plus a masked preview, and the event payload keeps only the preview.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuthAttempt, Event, Honeypot, Session
from app.schemas.agent import EventIn
from app.security.passwords import hash_token
from app.services import geoip, mitre

# Redis channels consumed by the realtime layer.
CHANNEL_ALL = "events:all"


def _channel_for(honeypot_id) -> str:
    return f"events:{honeypot_id}"


def mask_secret(value: str | None) -> str | None:
    if not value:
        return None
    if len(value) <= 2:
        return "*" * len(value)
    return value[0] + "*" * (len(value) - 2) + value[-1]


async def mark_seen(db: AsyncSession, hp: Honeypot) -> None:
    hp.last_seen_at = datetime.now(timezone.utc)
    hp.status = "online"


def _aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


async def _ensure_session(
    db: AsyncSession,
    hp: Honeypot,
    session_id: uuid.UUID | None,
    *,
    service: str | None = None,
    source_ip: str | None = None,
    started_at: datetime | None = None,
) -> None:
    if session_id is None:
        return
    existing = await db.get(Session, session_id)
    if existing is None:
        db.add(
            Session(
                id=session_id,
                honeypot_id=hp.id,
                service=service or "unknown",
                source_ip=source_ip,
                started_at=started_at or datetime.now(timezone.utc),
            )
        )
        await db.flush()


async def _publish(redis, hp: Honeypot, row: Event, occurred: datetime) -> None:
    if redis is None:
        return
    message = json.dumps(
        {
            "type": "event",
            "data": {
                "id": row.id,
                "honeypot_id": str(hp.id),
                "session_id": str(row.session_id) if row.session_id else None,
                "event_type": row.event_type,
                "source_ip": row.source_ip,
                "source_port": row.source_port,
                "dest_port": row.dest_port,
                "protocol": row.protocol,
                "severity": row.severity,
                "technique": row.technique,
                "source_country": row.source_country,
                "source_asn": row.source_asn,
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
            dup = await db.execute(select(Event.id).where(Event.dedup_key == ev.dedup_key))
            if dup.scalar_one_or_none() is not None:
                continue  # already stored (buffered re-delivery, FR-A4)

        occurred = _aware(ev.occurred_at)
        payload = dict(ev.payload or {})

        # Session lifecycle: materialize, don't add a feed event.
        if ev.event_type == "session_start":
            await _ensure_session(
                db, hp, ev.session_id,
                service=payload.get("service"),
                source_ip=ev.source_ip,
                started_at=occurred,
            )
            accepted += 1
            continue
        if ev.event_type == "session_end":
            if ev.session_id:
                sess = await db.get(Session, ev.session_id)
                if sess is not None:
                    sess.ended_at = occurred
            accepted += 1
            continue

        # Any event referencing a session must have the session row (FK).
        if ev.session_id:
            await _ensure_session(
                db, hp, ev.session_id, source_ip=ev.source_ip, started_at=occurred
            )

        if ev.event_type == "auth_attempt":
            password = payload.pop("password", None)
            preview = mask_secret(password)
            db.add(
                AuthAttempt(
                    session_id=ev.session_id,
                    honeypot_id=hp.id,
                    username=payload.get("username"),
                    password_hash=hash_token(password) if password else None,
                    password_preview=preview,
                    success=bool(payload.get("success", False)),
                    occurred_at=occurred,
                )
            )
            if preview is not None:
                payload["password_masked"] = preview
        elif ev.event_type == "http_request":
            # Scrub any posted password down to a preview.
            pw = payload.pop("password", None)
            if pw is not None:
                payload["password_masked"] = mask_secret(pw)

        asn, country, _org = geoip.lookup(ev.source_ip)
        row = Event(
            honeypot_id=hp.id,
            event_type=ev.event_type,
            source_ip=ev.source_ip,
            source_port=ev.source_port,
            dest_port=ev.dest_port,
            protocol=ev.protocol,
            severity=ev.severity,
            session_id=ev.session_id,
            payload=payload,
            technique=mitre.classify(ev.event_type, payload),
            source_country=country,
            source_asn=asn,
            occurred_at=occurred,
            dedup_key=ev.dedup_key,
        )
        db.add(row)
        await db.flush()
        accepted += 1
        await _publish(redis, hp, row, occurred)

    return accepted
