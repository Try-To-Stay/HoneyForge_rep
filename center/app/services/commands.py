"""Command channel center -> honeypot (TЗ §7.3 output data).

Commands are queued by the operator, delivered to the agent in its telemetry
response, executed by the agent, and acknowledged on the next beacon.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Command, Honeypot
from app.schemas.agent import CommandOut

VALID_ACTIONS = {"stop", "start", "rotate_creds", "refresh"}


async def pending_for(db: AsyncSession, hp: Honeypot) -> list[CommandOut]:
    rows = (
        await db.execute(
            select(Command)
            .where(Command.honeypot_id == hp.id, Command.status == "pending")
            .order_by(Command.created_at)
        )
    ).scalars().all()
    now = datetime.now(timezone.utc)
    out = []
    for c in rows:
        if c.delivered_at is None:
            c.delivered_at = now
        out.append(CommandOut(id=c.id, action=c.action, params=c.params or {}))
    return out


async def ack(db: AsyncSession, ids: list[int]) -> None:
    if not ids:
        return
    rows = (await db.execute(select(Command).where(Command.id.in_(ids)))).scalars().all()
    now = datetime.now(timezone.utc)
    for c in rows:
        c.status = "done"
        c.done_at = now
