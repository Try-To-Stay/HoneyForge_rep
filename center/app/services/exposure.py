"""Self-defense: detect when an attacker is hunting for the honeypot, and
re-mask on detection (feature #4).

An advanced attacker who suspects a honeypot probes for tells: listing
processes, inspecting outbound connections, detecting a VM/container, grepping
for monitoring/honeypot artifacts. We score those recon actions; past a
threshold we raise a `honeypot_probe` alert and (optionally) rotate the agent's
disguise (process name) so the tells the attacker just learned go stale.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.models import Alert, Honeypot
from app.schemas.agent import EventIn
from app.services.telemetry import CHANNEL_ALL

settings = get_settings()

# Substrings in commands that indicate hunting for monitoring / honeypot tells.
_RECON = [
    "ps aux", "ps -ef", "ps -e", "top", "htop", "ls /proc", "ls -la /proc",
    "netstat", "ss -", "ss\n", "lsof", "tcpdump",
    "systemd-detect-virt", "virt-what", "dmidecode", "/proc/cpuinfo",
    "/proc/1/cgroup", "dmesg", "lscpu",
    "honeypot", "cowrie", "canary", "kippo", "tpot",
    "bash_history", "last", "w\n", "who\n", "env\n", "printenv",
    "crontab", "systemctl status", "journalctl",
]

_DISGUISE_POOL = [
    "systemd-timesyncd", "dbus-daemon", "rsyslogd", "chronyd",
    "systemd-resolved", "cron", "systemd-logind",
]


def _is_recon(cmd: str) -> bool:
    low = cmd.strip().lower()
    return any(ind in low for ind in _RECON)


async def _publish_alert(redis, alert: Alert) -> None:
    if redis is None:
        return
    try:
        await redis.publish(
            CHANNEL_ALL,
            json.dumps(
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
            ),
        )
    except Exception:  # noqa: BLE001
        pass


def _rotate_disguise(hp: Honeypot) -> str:
    choices = [n for n in _DISGUISE_POOL if n != hp.disguise_name]
    new_name = random.choice(choices)
    hp.disguise_name = new_name
    return new_name


async def evaluate(db: AsyncSession, redis, hp: Honeypot, events: list[EventIn]) -> None:
    if not settings.selfdefense_enabled:
        return

    recon_srcs: dict[str, int] = {}
    for ev in events:
        if ev.event_type == "command" and _is_recon(str(ev.payload.get("command", ""))):
            recon_srcs[ev.source_ip or "?"] = recon_srcs.get(ev.source_ip or "?", 0) + 1

    if not recon_srcs:
        return

    hits = sum(recon_srcs.values())
    hp.exposure_score = (hp.exposure_score or 0) + hits

    if hp.exposure_score < settings.selfdefense_probe_threshold:
        return

    # Don't spam: only one probe alert per honeypot within the window.
    window_start = datetime.now(timezone.utc) - timedelta(seconds=settings.alert_window_s)
    recent = await db.execute(
        select(Alert.id).where(
            Alert.honeypot_id == hp.id,
            Alert.rule == "honeypot_probe",
            Alert.created_at >= window_start,
        )
    )
    if recent.first() is not None:
        return

    top_src = max(recon_srcs, key=recon_srcs.get)
    detail = f"recon for monitoring detected (score {hp.exposure_score})"
    if settings.selfdefense_auto_rotate:
        new_name = _rotate_disguise(hp)
        detail += f"; disguise rotated -> {new_name}"

    alert = Alert(
        honeypot_id=hp.id,
        source_ip=None if top_src == "?" else top_src,
        rule="honeypot_probe",
        severity="high",
        message=f"Honeypot may be detected: {detail}",
        event_count=hp.exposure_score,
    )
    db.add(alert)
    await db.flush()
    await _publish_alert(redis, alert)
