"""Event construction shared by honeypots. Shape matches center EventIn."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone


def make_event(
    event_type: str,
    *,
    source_ip: str | None = None,
    source_port: int | None = None,
    dest_port: int | None = None,
    protocol: str | None = None,
    severity: str = "info",
    session_id: str | None = None,
    payload: dict | None = None,
) -> dict:
    return {
        "dedup_key": str(uuid.uuid4()),
        "event_type": event_type,
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "source_port": source_port,
        "dest_port": dest_port,
        "protocol": protocol,
        "severity": severity,
        "session_id": session_id,
        "payload": payload or {},
    }
