"""fake-SSH honeypot (Medium, FR-A1/FR-A2) built on asyncssh.

Captures login attempts (credentials), opens a fake interactive shell on a
matching credential, and logs every command against a session. Nothing runs on
the real host — commands are served by FakeShell.
"""
from __future__ import annotations

import asyncio
import logging
import random
import uuid
from typing import Awaitable, Callable

import asyncssh

from honeypots.common.events import make_event
from honeypots.medium.fake_fs import CANARY_PATHS, CANARY_TOKEN, FakeShell

log = logging.getLogger("honeypot.ssh")

EmitFn = Callable[[dict], Awaitable[None]]

# Per-connection session info keyed by peername (ip, port).
_SESSIONS: dict[tuple, dict] = {}


class _HoneySSHServer(asyncssh.SSHServer):
    def __init__(self, emit: EmitFn, creds: list[dict], port: int):
        self._emit = emit
        self._creds = creds
        self._port = port
        self._peer: tuple | None = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._peer = conn.get_extra_info("peername")
        sid = str(uuid.uuid4())
        _SESSIONS[self._peer] = {
            "session_id": sid,
            "src_ip": self._peer[0],
            "src_port": self._peer[1],
        }
        asyncio.create_task(
            self._emit(
                make_event(
                    "session_start",
                    source_ip=self._peer[0],
                    source_port=self._peer[1],
                    dest_port=self._port,
                    protocol="ssh",
                    session_id=sid,
                    payload={"service": "ssh"},
                )
            )
        )

    def connection_lost(self, exc: Exception | None) -> None:
        info = _SESSIONS.pop(self._peer, None)
        if info:
            asyncio.create_task(
                self._emit(
                    make_event(
                        "session_end",
                        source_ip=info["src_ip"],
                        protocol="ssh",
                        session_id=info["session_id"],
                    )
                )
            )

    def begin_auth(self, username: str) -> bool:
        return True  # always require a password (so we capture attempts)

    def password_auth_supported(self) -> bool:
        return True

    async def validate_password(self, username: str, password: str) -> bool:
        info = _SESSIONS.get(self._peer, {})
        ok = any(
            username == c.get("username") and password == c.get("password")
            for c in self._creds
        )
        # Anti-fingerprinting (MASK-6): jitter the auth response time so success
        # and failure aren't trivially distinguishable by timing.
        await asyncio.sleep(random.uniform(0.1, 0.5))
        await self._emit(
            make_event(
                "auth_attempt",
                source_ip=info.get("src_ip"),
                source_port=info.get("src_port"),
                dest_port=self._port,
                protocol="ssh",
                severity="medium",
                session_id=info.get("session_id"),
                payload={"username": username, "password": password, "success": ok},
            )
        )
        return ok


def _make_shell_handler(emit: EmitFn, port: int):
    async def handle(process: asyncssh.SSHServerProcess) -> None:
        peer = process.get_extra_info("peername")
        info = _SESSIONS.get(peer, {})
        sid = info.get("session_id")
        username = process.get_extra_info("username") or "root"
        shell = FakeShell(user=username)

        process.stdout.write("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n")
        try:
            while not process.stdin.at_eof():
                process.stdout.write(shell.prompt() + " ")
                try:
                    line = await process.stdin.readline()
                except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged):
                    continue
                except Exception:  # noqa: BLE001
                    break
                if not line:
                    break
                cmd = line.strip()
                if not cmd:
                    continue
                await emit(
                    make_event(
                        "command",
                        source_ip=info.get("src_ip"),
                        dest_port=port,
                        protocol="ssh",
                        severity="medium",
                        session_id=sid,
                        payload={"command": cmd},
                    )
                )

                # Honeytoken (FR-A6): reading the canary credential file fires a
                # high-signal token_trigger event.
                parts = cmd.split()
                if len(parts) >= 2 and parts[0] == "cat" and shell.resolve(parts[1]) in CANARY_PATHS:
                    await emit(
                        make_event(
                            "token_trigger",
                            source_ip=info.get("src_ip"),
                            dest_port=port,
                            protocol="ssh",
                            severity="high",
                            session_id=sid,
                            payload={"token": CANARY_TOKEN, "path": shell.resolve(parts[1])},
                        )
                    )

                out = shell.run(cmd)
                if out == "__EXIT__":
                    process.stdout.write("logout\r\n")
                    break
                if out:
                    process.stdout.write(out.replace("\r\n", "\n").replace("\n", "\r\n") + "\r\n")
        finally:
            process.exit(0)

    return handle


class SSHHoneypot:
    def __init__(self, service: dict, emit: EmitFn):
        self._service = service
        self._emit = emit
        self._server: asyncssh.SSHAcceptor | None = None

    async def start(self) -> None:
        port = int(self._service.get("port", 22))
        creds = self._service.get("fake_credentials", [{"username": "admin", "password": "admin123"}])
        host_key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)

        self._server = await asyncssh.create_server(
            lambda: _HoneySSHServer(self._emit, creds, port),
            "0.0.0.0",
            port,
            server_host_keys=[host_key],
            # Software-version string (no spaces); asyncssh sends "SSH-2.0-<this>".
            server_version="OpenSSH_8.9p1",
            process_factory=_make_shell_handler(self._emit, port),
        )
        log.info("fake-SSH honeypot listening on tcp/%s", port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
