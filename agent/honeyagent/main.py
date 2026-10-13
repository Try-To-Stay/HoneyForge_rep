"""Agent orchestrator.

Enrolls with the center over the disguised TLS channel, starts the honeypot
from the delivered profile config, then runs a beacon/flush loop that drains
the durable buffer. Connectivity loss only delays delivery; nothing is lost
(FR-A3, FR-A4).
"""
from __future__ import annotations

import asyncio
import logging
import os
import random
import secrets
import time
from datetime import datetime, timezone

from honeyagent.buffer import Buffer
from honeyagent.config import AgentConfig
from honeyagent.stealth import set_process_name
from honeyagent.transport import Transport
from honeypots.high.ssh_server import HighSSHHoneypot
from honeypots.low.listener import LowHoneypot
from honeypots.medium.http_admin import HTTPHoneypot
from honeypots.medium.mysql_server import MySQLHoneypot
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


def _save_mtls(cfg, mtls: dict) -> str:
    """Persist CA + client cert/key; return the cert_expires_at string."""
    os.makedirs(os.path.dirname(cfg.ca_path) or ".", exist_ok=True)
    for path, content in (
        (cfg.ca_path, mtls["ca_cert"]),
        (cfg.client_cert_path, mtls["client_cert"]),
        (cfg.client_key_path, mtls["client_key"]),
    ):
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    try:
        os.chmod(cfg.client_key_path, 0o600)
    except Exception:  # noqa: BLE001
        pass
    return mtls.get("cert_expires_at", "")


def _needs_rotation(expires_iso: str, margin_s: int) -> bool:
    if not expires_iso:
        return False
    try:
        exp = datetime.fromisoformat(expires_iso)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return (exp - datetime.now(timezone.utc)).total_seconds() < margin_s


def _build_honeypots(services: list[dict], emit, upload=None):
    """Instantiate honeypots from the profile's service list.

    Plain TCP banner services are handled together by the Low honeypot; ssh and
    http services each get their Medium honeypot. High gets a file-upload hook.
    """
    honeypots: list = []
    tcp_services = [s for s in services if s.get("type") in (None, "tcp")]
    if tcp_services:
        honeypots.append(LowHoneypot(tcp_services, emit))
    for svc in services:
        if svc.get("type") == "ssh":
            honeypots.append(SSHHoneypot(svc, emit))
        elif svc.get("type") == "ssh_high":
            honeypots.append(HighSSHHoneypot(svc, emit, upload))
        elif svc.get("type") == "http":
            honeypots.append(HTTPHoneypot(svc, emit))
        elif svc.get("type") == "mysql":
            honeypots.append(MySQLHoneypot(svc, emit))
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

    # mTLS (MASK-7): if the center issued a client cert, persist it, pin the CA
    # and switch the transport to mutual TLS for all subsequent requests.
    cert_expires = ""
    if cfg.mtls_enabled and data.get("mtls"):
        cert_expires = _save_mtls(cfg, data["mtls"])
        await transport.rebuild()
        log.info("mTLS enabled; client cert expires %s", cert_expires)

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

    async def upload(filename: str, content_b64: str, session_id: str | None = None) -> None:
        try:
            await transport.upload_artifact(agent_key, filename, content_b64, session_id)
            log.info("uploaded artifact %s", filename)
        except Exception as exc:  # noqa: BLE001
            log.warning("artifact upload failed (%s): %s", filename, exc)

    honeypots = _build_honeypots(config.get("services", []), emit, upload)
    for hp in honeypots:
        await hp.start()

    async def run_command(cmd: dict) -> None:
        """Execute a management command from the center (command channel)."""
        action = cmd.get("action")
        if action == "stop":
            for hp in honeypots:
                await hp.stop()
            log.info("command: stopped honeypot listeners")
        elif action == "start":
            for hp in honeypots:
                await hp.start()
            log.info("command: started honeypot listeners")
        elif action == "rotate_creds":
            newpw = secrets.token_urlsafe(9)
            for hp in honeypots:
                if isinstance(hp, SSHHoneypot):
                    await hp.stop()
                    hp.set_credentials([{"username": "admin", "password": newpw}])
                    await hp.start()
            log.info("command: rotated decoy SSH credentials")
        elif action == "refresh":
            log.info("command: config refresh requested")

    acks: list[int] = []

    async def sender() -> None:
        nonlocal etag, cert_expires
        while True:
            await asyncio.sleep(_next_interval(cfg))

            # Rotate the client cert before it expires (MASK-7).
            if cfg.mtls_enabled and _needs_rotation(cert_expires, cfg.cert_renew_margin_s):
                try:
                    fresh = await transport.rotate(agent_key)
                    cert_expires = _save_mtls(cfg, fresh)
                    await transport.rebuild()
                    log.info("rotated client cert; new expiry %s", cert_expires)
                except Exception as exc:  # noqa: BLE001
                    log.warning("cert rotation failed: %s", exc)

            pending = await buffer.pending(cfg.send_batch)
            ids = [i for i, _ in pending]
            events = [e for _, e in pending]
            beacon = {"uptime_s": int(time.time() - started_at), "hp_status": "ok"}
            acks_to_send = list(acks)
            try:
                resp = await transport.send_telemetry(agent_key, beacon, events, acks_to_send)
                if ids:
                    await buffer.delete(ids)
                    log.info("sent %d event(s)", len(ids))
                for i in acks_to_send:
                    if i in acks:
                        acks.remove(i)
                # Execute any commands the center queued, ack them next beacon.
                for cmd in resp.get("commands", []):
                    try:
                        await run_command(cmd)
                        acks.append(cmd["id"])
                    except Exception as exc:  # noqa: BLE001
                        log.warning("command %s failed: %s", cmd.get("action"), exc)
                new_etag = resp.get("config_etag")
                if new_etag and new_etag != etag:
                    log.info("config changed (etag %s -> %s); refetching", etag, new_etag)
                    try:
                        fresh = await transport.get_config(agent_key)
                        etag = fresh.get("config_etag")
                        fresh_masking = (fresh.get("config") or {}).get("masking") or {}
                        # Re-apply the (possibly rotated) disguise live — self-defense
                        # re-masking (feature #4). Service changes still need a restart.
                        new_name = fresh_masking.get("process_name")
                        if new_name:
                            set_process_name(new_name)
                            log.info("disguise re-applied: process name -> %s", new_name)
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
