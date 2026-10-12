"""High-interaction fake-SSH honeypot (Bonus FR-A5).

Unlike Medium (which returns canned output from a fake shell), High executes
the attacker's commands **for real** inside a disposable sandbox container, so
they see a genuine OS. Safety is by strict isolation, not emulation:

- one throwaway container per session (`--rm`), destroyed on disconnect
  (auto-reset "snapshot");
- `--network none` so the attacker can never reach out (no exfil/C2);
- memory / CPU / PID limits and `--cap-drop ALL`;
- no host mounts.

The full session is recorded to the agent's data volume. Lab-only: the agent
host needs the Docker socket and the `docker` CLI. NOT for shared/production
hosts.
"""
from __future__ import annotations

import asyncio
import logging
import os
import uuid

import asyncssh

from honeypots.common.events import make_event
from honeypots.medium.ssh_server import _SESSIONS, _HoneySSHServer

log = logging.getLogger("honeypot.high")

SANDBOX_IMAGE = os.getenv("HIGH_SANDBOX_IMAGE", "alpine:3.20")
REC_DIR = os.getenv("HIGH_RECORDINGS_DIR", "/data/recordings")
CMD_TIMEOUT_S = int(os.getenv("HIGH_CMD_TIMEOUT_S", "15"))


async def _run_capture(*args: str, timeout: int = CMD_TIMEOUT_S) -> bytes:
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
        return out
    except asyncio.TimeoutError:
        proc.kill()
        return b"(command timed out)\n"


async def _spawn_sandbox(name: str) -> bool:
    proc = await asyncio.create_subprocess_exec(
        "docker", "run", "-d", "--rm", "--name", name,
        "--network", "none",
        "--memory", "128m", "--cpus", "0.5", "--pids-limit", "64",
        "--cap-drop", "ALL",
        SANDBOX_IMAGE, "sleep", "3600",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    _, err = await proc.communicate()
    if proc.returncode != 0:
        log.warning("sandbox spawn failed: %s", err.decode(errors="replace")[:200])
        return False
    return True


async def _destroy_sandbox(name: str) -> None:
    proc = await asyncio.create_subprocess_exec(
        "docker", "rm", "-f", name,
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.communicate()


def _make_handler(emit, port: int):
    async def handle(process: asyncssh.SSHServerProcess) -> None:
        peer = process.get_extra_info("peername")
        info = _SESSIONS.get(peer, {})
        sid = info.get("session_id") or str(uuid.uuid4())
        cname = f"hf-sbx-{uuid.uuid4().hex[:10]}"

        if not await _spawn_sandbox(cname):
            process.stdout.write("Unable to allocate a session, try again later.\r\n")
            process.exit(1)
            return

        os.makedirs(REC_DIR, exist_ok=True)
        rec_path = os.path.join(REC_DIR, f"{sid}.log")
        rec = open(rec_path, "a", encoding="utf-8", errors="replace")
        prompt = f"root@{cname[:12]}:~# "
        process.stdout.write("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n")
        try:
            while not process.stdin.at_eof():
                process.stdout.write(prompt)
                try:
                    line = await process.stdin.readline()
                except Exception:  # noqa: BLE001
                    break
                if not line:
                    break
                cmd = line.strip()
                if not cmd:
                    continue
                rec.write(f"$ {cmd}\n")
                await emit(
                    make_event(
                        "command",
                        source_ip=info.get("src_ip"),
                        dest_port=port,
                        protocol="ssh",
                        severity="high",
                        session_id=sid,
                        payload={"command": cmd, "interaction": "high"},
                    )
                )
                if cmd in ("exit", "logout", "quit"):
                    break
                out = await _run_capture("docker", "exec", cname, "/bin/sh", "-c", cmd)
                text = out.decode(errors="replace")
                rec.write(text)
                if text:
                    process.stdout.write(text.replace("\r\n", "\n").replace("\n", "\r\n"))
        finally:
            try:
                rec.close()
            except Exception:  # noqa: BLE001
                pass
            await _destroy_sandbox(cname)  # auto-reset
            await emit(
                make_event(
                    "session_recording",
                    source_ip=info.get("src_ip"),
                    dest_port=port,
                    protocol="ssh",
                    severity="info",
                    session_id=sid,
                    payload={"path": rec_path},
                )
            )
            process.exit(0)

    return handle


class HighSSHHoneypot:
    def __init__(self, service: dict, emit):
        self._service = service
        self._emit = emit
        self._server: asyncssh.SSHAcceptor | None = None

    async def start(self) -> None:
        port = int(self._service.get("port", 22))
        creds = self._service.get("fake_credentials", [{"username": "root", "password": "toor"}])
        host_key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
        self._server = await asyncssh.create_server(
            lambda: _HoneySSHServer(self._emit, creds, port),
            "0.0.0.0",
            port,
            server_host_keys=[host_key],
            server_version="OpenSSH_8.9p1",
            process_factory=_make_handler(self._emit, port),
        )
        log.info("high-interaction SSH honeypot listening on tcp/%s (sandbox=%s)", port, SANDBOX_IMAGE)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
