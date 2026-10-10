"""Low-interaction honeypot: TCP listeners that present a banner and record
the fact of a scan/connection (FR-A1, level Low)."""
from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable

from honeypots.common.events import make_event

log = logging.getLogger("honeypot.low")

EmitFn = Callable[[dict], Awaitable[None]]


class LowHoneypot:
    def __init__(self, services: list[dict], emit: EmitFn):
        self._services = services
        self._emit = emit
        self._servers: list[asyncio.base_events.Server] = []

    async def start(self) -> None:
        for svc in self._services:
            if svc.get("type") not in (None, "tcp"):
                continue  # Low handles plain TCP banners only
            port = int(svc["port"])
            banner = svc.get("banner", "")
            server = await asyncio.start_server(
                self._make_handler(port, banner), host="0.0.0.0", port=port
            )
            self._servers.append(server)
            log.info("Low honeypot listening on tcp/%s", port)

    def _make_handler(self, dest_port: int, banner: str):
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            peer = writer.get_extra_info("peername")
            src_ip = peer[0] if peer else None
            src_port = peer[1] if peer and len(peer) > 1 else None
            try:
                if banner:
                    writer.write(banner.encode(errors="ignore"))
                    await writer.drain()
                # Give the client a moment; capture any probe bytes it sends.
                try:
                    data = await asyncio.wait_for(reader.read(512), timeout=2.0)
                except asyncio.TimeoutError:
                    data = b""
                event_type = "connect" if data else "scan"
                await self._emit(
                    make_event(
                        event_type,
                        source_ip=src_ip,
                        source_port=src_port,
                        dest_port=dest_port,
                        protocol="tcp",
                        severity="low",
                        payload={
                            "banner_sent": banner,
                            "probe": data.decode(errors="replace")[:200] if data else "",
                        },
                    )
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("handler error on tcp/%s: %s", dest_port, exc)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass

        return handle

    async def stop(self) -> None:
        for server in self._servers:
            server.close()
        for server in self._servers:
            try:
                await server.wait_closed()
            except Exception:  # noqa: BLE001
                pass
