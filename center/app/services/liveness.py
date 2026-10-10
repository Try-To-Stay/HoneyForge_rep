"""Derive honeypot online/offline status from last beacon time."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.config import get_settings
from app.db.models import Honeypot

settings = get_settings()


def effective_status(hp: Honeypot) -> str:
    """online if a beacon arrived within the TTL, else offline (or unknown)."""
    if hp.last_seen_at is None:
        return "unknown"
    last = hp.last_seen_at
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    threshold = datetime.now(timezone.utc) - timedelta(seconds=settings.honeypot_offline_ttl_s)
    return "online" if last >= threshold else "offline"
