"""Agent orchestrator.

Enrolls with the center over the disguised TLS channel, starts the honeypot
from the delivered profile config, then runs a beacon/flush loop that drains
the durable buffer. Connectivity loss only delays delivery; nothing is lost
(FR-A3, FR-A4).
"""
from __future__ import annotations

import asyncio
import logging
import random
import time

from honeyagent.buffer import Buffer
from honeyagent.config import AgentConfig
from honeyagent.stealth import set_process_name
from honeyagent.transport import Transport
from honeypots.low.listener import LowHoneypot
from honeypots.medium.http_admin import HTTPHoneypot
from honeypots.medium.ssh_server import SSHHoneypot

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("honeyagent")


async def _enroll_with_retry(transport: Transport, token: str) -> dict:
    delay = 5
    while True:
        try:
            return await transport.enroll(token)
        except Exception as exc:  # noqa: BLE001
            log.warning("enroll failed (%s); retry in %ds", exc, delay)
            await asyncio.sleep(delay)


def _build_honeypots(services: list[dict], emit):
    """Instantiate honeypots from the profile's service list.

    Plain TCP banner services are handled together by the Low honeypot; ssh and
    http services each get their Medium honeypot.
    """
    honeypots: list = []
    tcp_services = [s for s in services if s.get("type") in (None, "tcp")]
    if tcp_services:
        honeypots.append(LowHoneypot(tcp_services, emit))
    for svc in services:
        if svc.get("type") == "ssh":
            honeypots.append(SSHHoneypot(svc, emit))
        elif svc.get("type") == "http":
            honeypots.append(HTTPHoneypot(svc, emit))
    return honeypots


def _next_interval(cfg: AgentConfig) -> float:
    if cfg.jitter_max_s and cfg.jitter_max_s > 0:
        lo = cfg.jitter_min_s or cfg.beacon_interval_s
        return random.randint(min(lo, cfg.jitter_max_s), cfg.jitter_max_s)
    return cfg.beacon_interval_s


async def run() -> None:
    cfg = AgentConfig()
    if not cfg.enroll_token:
        raise SystemExit("HONEYFORGE_ENROLL_TOKEN is not set")

    buffer = Buffer(cfg.buffer_path)
    transport = Transport(cfg)
    started_at = time.time()

    data = await _enroll_with_retry(transport, cfg.enroll_token)
    agent_key = data["agent_key"]
    etag = data.get("config_etag")
    config = data.get("config", {})
    log.info("enrolled as %s (etag=%s)", data.get("agent_id"), etag)

    masking = config.get("masking") or {}
    # Host-side stealth (MASK-4): adopt an innocuous process name from the profile.
    set_process_name(masking.get("process_name"))

    # Beacon jitter (MASK-5): randomize the beacon interval from the profile so
    # the channel has no fixed, fingerprintable period. Env overrides if set.
    jitter = masking.get("beacon_jitter_s")
    if (
        cfg.jitter_max_s == 0
        and isinstance(jitter, (list, tuple))
        and len(jitter) == 2
    ):
        cfg.jitter_min_s, cfg.jitter_max_s = int(jitter[0]), int(jitter[1])
        log.info("beacon jitter %s-%ss", cfg.jitter_min_s, cfg.jitter_max_s)

    async def emit(event: dict) -> None:
        await buffer.enqueue(event)

    honeypots = _build_honeypots(config.get("services", []), emit)
    for hp in honeypots:
        await hp.start()

    async def sender() -> None:
        nonlocal etag
        while True:
            await asyncio.sleep(_next_interval(cfg))
            pending = await buffer.pending(cfg.send_batch)
            ids = [i for i, _ in pending]
            events = [e for _, e in pending]
            beacon = {"uptime_s": int(time.time() - started_at), "hp_status": "ok"}
            try:
                resp = await transport.send_telemetry(agent_key, beacon, events)
                if ids:
                    await buffer.delete(ids)
                    log.info("sent %d event(s)", len(ids))
                new_etag = resp.get("config_etag")
                if new_etag and new_etag != etag:
                    log.info("config changed (etag %s -> %s); refetching", etag, new_etag)
                    try:
                        fresh = await transport.get_config(agent_key)
                        etag = fresh.get("config_etag")
                        log.info("config updated; restart required to apply service changes")
                    except Exception as exc:  # noqa: BLE001
                        log.warning("config refetch failed: %s", exc)
            except Exception as exc:  # noqa: BLE001
                backlog = await buffer.count()
                log.warning("telemetry send failed (%s); %d event(s) buffered", exc, backlog)

    try:
        await sender()
    finally:
        for hp in honeypots:
            await hp.stop()
        await transport.aclose()


if __name__ == "__main__":
    asyncio.run(run())
