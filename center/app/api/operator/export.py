"""IoC export in CSV and STIX 2.1 (Bonus FR-C7).

Indicators are the distinct attacker source IPs observed, with counts and
first/last-seen. STIX output is a minimal but valid 2.1 bundle of Indicator
SDOs so it can be imported into a TIP.
"""
from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, Response
from sqlalchemy import func, select

from app.db.models import Event
from app.security.deps import CurrentOperator, DbSession

router = APIRouter(prefix="/export", tags=["export"])


async def _source_indicators(db: DbSession) -> list[dict]:
    rows = (
        await db.execute(
            select(
                Event.source_ip,
                func.count(Event.id),
                func.min(Event.occurred_at),
                func.max(Event.occurred_at),
            )
            .where(Event.source_ip.is_not(None))
            .group_by(Event.source_ip)
            .order_by(func.count(Event.id).desc())
        )
    ).all()
    return [
        {
            "type": "ipv4-addr",
            "value": str(ip),
            "count": count,
            "first_seen": first,
            "last_seen": last,
        }
        for ip, count, first, last in rows
    ]


@router.get("/iocs")
async def export_iocs(
    current: CurrentOperator,
    db: DbSession,
    format: str = Query(default="csv", pattern="^(csv|stix)$"),
):
    indicators = await _source_indicators(db)

    if format == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["type", "value", "count", "first_seen", "last_seen"])
        for ind in indicators:
            writer.writerow(
                [
                    ind["type"],
                    ind["value"],
                    ind["count"],
                    ind["first_seen"].isoformat() if ind["first_seen"] else "",
                    ind["last_seen"].isoformat() if ind["last_seen"] else "",
                ]
            )
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=honeyforge-iocs.csv"},
        )

    if format == "stix":
        now = datetime.now(timezone.utc).isoformat()
        objects = []
        for ind in indicators:
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{uuid.uuid4()}",
                    "created": now,
                    "modified": now,
                    "name": f"Honeypot source {ind['value']}",
                    "description": f"Observed {ind['count']} event(s) on HoneyForge honeypots",
                    "indicator_types": ["malicious-activity"],
                    "pattern": f"[ipv4-addr:value = '{ind['value']}']",
                    "pattern_type": "stix",
                    "valid_from": ind["first_seen"].isoformat() if ind["first_seen"] else now,
                }
            )
        bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
        return Response(
            content=json.dumps(bundle, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=honeyforge-iocs.stix.json"},
        )

    raise HTTPException(status_code=400, detail="unsupported format")
