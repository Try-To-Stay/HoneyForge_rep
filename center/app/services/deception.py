"""Adaptive deception ladder (feature #3).

When a high-signal alert fires (honeytoken or brute force), the platform
responds automatically: it spins up an extra decoy honeypot from a profile and
logs the action — turning a single trap into an expanding web of them around
the attacker. Bounded by a cap and per-source de-duplication so it can't run
away. Requires the orchestrator (Docker socket); off by default on prod.
"""
from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.models import Alert, DeceptionAction, Honeypot, Profile
from app.security.passwords import hash_token
from app.services import orchestrator
from app.services.telemetry import CHANNEL_ALL

settings = get_settings()

TRIGGER_RULES = {"brute_force", "honeytoken"}


async def _publish(redis, action: DeceptionAction) -> None:
    if redis is None:
        return
    try:
        await redis.publish(
            CHANNEL_ALL,
            json.dumps(
                {
                    "type": "deception",
                    "data": {
                        "id": action.id,
                        "action": action.action,
                        "source_ip": action.source_ip,
                        "honeypot_id": str(action.honeypot_id) if action.honeypot_id else None,
                        "detail": action.detail,
                        "created_at": action.created_at.isoformat() if action.created_at else None,
                    },
                },
                default=str,
            ),
        )
    except Exception:  # noqa: BLE001
        pass


async def evaluate(db: AsyncSession, redis, new_alerts: list[Alert]) -> None:
    if not settings.deception_enabled or not orchestrator.available():
        return
    triggers = [a for a in new_alerts if a.rule in TRIGGER_RULES]
    if not triggers:
        return

    deployed = (
        await db.execute(select(func.count(Honeypot.id)).where(Honeypot.auto_deployed.is_(True)))
    ).scalar_one()
    if deployed >= settings.deception_max_decoys:
        return

    window_start = datetime.now(timezone.utc) - timedelta(seconds=settings.deception_window_s)
    alert = triggers[0]  # one decoy per batch
    src = alert.source_ip

    recent = await db.execute(
        select(DeceptionAction.id).where(
            DeceptionAction.action == "deploy_decoy",
            DeceptionAction.source_ip == src,
            DeceptionAction.created_at >= window_start,
        )
    )
    if recent.first() is not None:
        return

    profile = (
        await db.execute(select(Profile).where(Profile.level == "low").limit(1))
    ).scalar_one_or_none()
    if profile is None:
        return

    enroll_token = secrets.token_urlsafe(32)
    short = secrets.token_hex(3)
    hp = Honeypot(
        name=f"decoy-{short}",
        profile_id=profile.id,
        host_label="auto-decoy",
        enroll_token_hash=hash_token(enroll_token),
        status="unknown",
        auto_deployed=True,
    )
    db.add(hp)
    await db.flush()

    try:
        container_id = await orchestrator.deploy_honeypot(str(hp.id), enroll_token)
    except Exception:  # noqa: BLE001 - remove the decoy row, keep events/alerts
        await db.delete(hp)
        await db.flush()
        return

    action = DeceptionAction(
        action="deploy_decoy",
        source_ip=src,
        honeypot_id=hp.id,
        alert_id=alert.id,
        detail={"container_id": container_id, "trigger_rule": alert.rule, "decoy": hp.name},
    )
    db.add(action)
    await db.flush()
    await _publish(redis, action)
