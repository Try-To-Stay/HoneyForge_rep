"""Attacker correlation across the fleet (feature #2).

Aggregates events by source IP across ALL honeypots, so the same attacker is
tracked wherever they land, with the MITRE techniques they used and a threat
score derived from breadth (how many honeypots) and depth (what they did).
"""
from __future__ import annotations

from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Event
from app.services import mitre


def _score(honeypots: int, techniques: int, commands: int, auths: int, tokens: int) -> int:
    raw = honeypots * 15 + techniques * 8 + commands * 2 + auths * 1 + tokens * 25
    return min(100, raw)


async def list_attackers(db: AsyncSession, limit: int = 50) -> list[dict]:
    rows = (
        await db.execute(
            select(
                Event.source_ip,
                func.count(Event.id).label("events"),
                func.count(distinct(Event.honeypot_id)).label("honeypots"),
                func.count(distinct(Event.technique)).label("techniques"),
                func.min(Event.occurred_at).label("first_seen"),
                func.max(Event.occurred_at).label("last_seen"),
                func.count(Event.id).filter(Event.event_type == "command").label("commands"),
                func.count(Event.id).filter(Event.event_type == "auth_attempt").label("auths"),
                func.count(Event.id).filter(Event.event_type == "token_trigger").label("tokens"),
            )
            .where(Event.source_ip.is_not(None))
            .group_by(Event.source_ip)
            .order_by(func.count(distinct(Event.honeypot_id)).desc(), func.count(Event.id).desc())
            .limit(limit)
        )
    ).all()

    out = []
    for r in rows:
        out.append(
            {
                "source_ip": str(r.source_ip),
                "events": r.events,
                "honeypots_touched": r.honeypots,
                "techniques": r.techniques,
                "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                "threat_score": _score(r.honeypots, r.techniques, r.commands, r.auths, r.tokens),
            }
        )
    return out


async def attacker_detail(db: AsyncSession, source_ip: str) -> dict | None:
    agg = (
        await db.execute(
            select(
                func.count(Event.id),
                func.count(distinct(Event.honeypot_id)),
                func.min(Event.occurred_at),
                func.max(Event.occurred_at),
                func.count(Event.id).filter(Event.event_type == "command"),
                func.count(Event.id).filter(Event.event_type == "auth_attempt"),
                func.count(Event.id).filter(Event.event_type == "token_trigger"),
            ).where(Event.source_ip == source_ip)
        )
    ).one()
    total = agg[0]
    if not total:
        return None

    tech_rows = (
        await db.execute(
            select(Event.technique, func.count(Event.id))
            .where(Event.source_ip == source_ip, Event.technique.is_not(None))
            .group_by(Event.technique)
            .order_by(func.count(Event.id).desc())
        )
    ).all()
    techniques = [
        {**(mitre.describe(t) or {"id": t, "name": t, "tactic": "?"}), "count": c}
        for t, c in tech_rows
    ]

    hp_rows = (
        await db.execute(
            select(Event.honeypot_id, func.count(Event.id))
            .where(Event.source_ip == source_ip)
            .group_by(Event.honeypot_id)
        )
    ).all()

    return {
        "source_ip": source_ip,
        "events": total,
        "honeypots_touched": agg[1],
        "first_seen": agg[2].isoformat() if agg[2] else None,
        "last_seen": agg[3].isoformat() if agg[3] else None,
        "threat_score": _score(agg[1], len(techniques), agg[4], agg[5], agg[6]),
        "techniques": techniques,
        "honeypots": [{"honeypot_id": str(hid), "events": c} for hid, c in hp_rows],
    }
