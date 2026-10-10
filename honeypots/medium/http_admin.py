"""fake-HTTP admin honeypot (Medium).

A minimal HTTP/1.1 server (stdlib asyncio, no deps) that serves a plausible
admin login page and logs credential submissions. Passwords are sent to the
center, which stores only a masked preview.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable
from urllib.parse import parse_qs

from honeypots.common.events import make_event

log = logging.getLogger("honeypot.http")

EmitFn = Callable[[dict], Awaitable[None]]

_LOGIN_PAGE = """<!doctype html>
<html><head><title>Admin Login</title></head>
<body style="font-family:sans-serif;max-width:360px;margin:80px auto">
<h2>Admin Console</h2>
<form method="POST" action="/admin">
<p><input name="username" placeholder="Username" style="width:100%;padding:8px"></p>
<p><input name="password" type="password" placeholder="Password" style="width:100%;padding:8px"></p>
<button style="padding:8px 16px">Sign in</button>
</form>
</body></html>"""


class HTTPHoneypot:
    def __init__(self, service: dict, emit: EmitFn):
        self._service = service
        self._emit = emit
        self._server: asyncio.base_events.Server | None = None
        self._server_header = service.get("server_header", "nginx/1.24.0")

    async def start(self) -> None:
        port = int(self._service.get("port", 80))
        self._server = await asyncio.start_server(self._handle, "0.0.0.0", port)
        log.info("fake-HTTP honeypot listening on tcp/%s", port)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        src_ip = peer[0] if peer else None
        src_port = peer[1] if peer and len(peer) > 1 else None
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            if not request_line:
                return
            try:
                method, path, _ = request_line.decode(errors="replace").split(" ", 2)
            except ValueError:
                return

            headers: dict[str, str] = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if line in (b"\r\n", b"\n", b""):
                    break
                if b":" in line:
                    k, v = line.decode(errors="replace").split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            body = b""
            clen = int(headers.get("content-length", 0) or 0)
            if clen > 0:
                body = await asyncio.wait_for(reader.readexactly(min(clen, 8192)), timeout=5.0)

            username = password = None
            if method == "POST":
                form = parse_qs(body.decode(errors="replace"))
                username = (form.get("username") or [None])[0]
                password = (form.get("password") or [None])[0]

            await self._emit(
                make_event(
                    "http_request",
                    source_ip=src_ip,
                    source_port=src_port,
                    dest_port=int(self._service.get("port", 80)),
                    protocol="http",
                    severity="medium" if method == "POST" else "low",
                    payload={
                        "method": method,
                        "path": path,
                        "user_agent": headers.get("user-agent", ""),
                        **({"username": username} if username else {}),
                        **({"password": password} if password else {}),
                    },
                )
            )

            if method == "POST":
                # Always "fail" the login — keep them guessing.
                self._respond(writer, 401, "text/html", _LOGIN_PAGE)
            else:
                self._respond(writer, 200, "text/html", _LOGIN_PAGE)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        except Exception as exc:  # noqa: BLE001
            log.warning("http handler error: %s", exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    def _respond(self, writer: asyncio.StreamWriter, status: int, ctype: str, body: str) -> None:
        reason = {200: "OK", 401: "Unauthorized", 404: "Not Found"}.get(status, "OK")
        data = body.encode()
        head = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Server: {self._server_header}\r\n"
            f"Content-Type: {ctype}\r\n"
            f"Content-Length: {len(data)}\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(head.encode() + data)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
