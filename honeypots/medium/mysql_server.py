"""fake-MySQL honeypot (Medium, FR-A1).

Speaks enough of the MySQL client/server wire protocol to look like a real
MySQL 5.7 server: it sends a proper handshake, captures the login (username)
and then logs every SQL query the client sends, as session-scoped events.

Note on passwords: MySQL scrambles the password on the client side
(mysql_native_password), so the plaintext isn't recoverable from a normal
login — we record the username and the queries (the high-value intel) and
keep an auth fingerprint. Everything runs on asyncio stdlib, no real DB.
"""
from __future__ import annotations

import asyncio
import logging
import os
import struct
import uuid
from typing import Awaitable, Callable

from honeypots.common.events import make_event

log = logging.getLogger("honeypot.mysql")

EmitFn = Callable[[dict], Awaitable[None]]

CLIENT_PROTOCOL_41 = 0x200
CLIENT_SECURE_CONNECTION = 0x8000
CLIENT_PLUGIN_AUTH = 0x80000
CLIENT_CONNECT_WITH_DB = 0x8

COM_QUIT = 0x01
COM_INIT_DB = 0x02
COM_QUERY = 0x03


async def _read_packet(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    header = await reader.readexactly(4)
    length = header[0] | (header[1] << 8) | (header[2] << 16)
    seq = header[3]
    payload = await reader.readexactly(length) if length else b""
    return seq, payload


def _packet(seq: int, payload: bytes) -> bytes:
    n = len(payload)
    return bytes([n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF, seq & 0xFF]) + payload


def _ok() -> bytes:
    # OK packet: header 0x00, affected_rows=0, last_insert_id=0, status=AUTOCOMMIT, warnings=0
    return b"\x00\x00\x00\x02\x00\x00\x00"


def _err(code: int, state: str, msg: str) -> bytes:
    return b"\xff" + struct.pack("<H", code) + b"#" + state.encode() + msg.encode()


class MySQLHoneypot:
    def __init__(self, service: dict, emit: EmitFn):
        self._service = service
        self._emit = emit
        self._port = int(service.get("port", 3306))
        self._version = service.get("banner", "5.7.42-log")
        self._server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "0.0.0.0", self._port)
        log.info("fake-MySQL honeypot listening on tcp/%s", self._port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    def _build_handshake(self, salt: bytes) -> bytes:
        caps = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH | CLIENT_CONNECT_WITH_DB
        p = bytearray()
        p += b"\x0a"                               # protocol version 10
        p += self._version.encode() + b"\x00"      # server version
        p += struct.pack("<I", 0x00000B37)         # connection id
        p += salt[:8]                              # auth-plugin-data part 1
        p += b"\x00"                               # filler
        p += struct.pack("<H", caps & 0xFFFF)      # capability flags (lower)
        p += b"\x21"                               # charset (utf8_general_ci)
        p += struct.pack("<H", 0x0002)             # status flags
        p += struct.pack("<H", (caps >> 16) & 0xFFFF)  # capability flags (upper)
        p += bytes([21])                           # length of auth-plugin-data
        p += b"\x00" * 10                          # reserved
        p += salt[8:20] + b"\x00"                  # auth-plugin-data part 2 (13 bytes)
        p += b"mysql_native_password\x00"
        return bytes(p)

    @staticmethod
    def _parse_username(data: bytes) -> str | None:
        # 4.1 handshake response: caps(4) max_pkt(4) charset(1) reserved(23) then username\0
        try:
            end = data.index(b"\x00", 32)
            return data[32:end].decode(errors="replace")
        except (ValueError, IndexError):
            return None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        src_ip = peer[0] if peer else None
        src_port = peer[1] if peer and len(peer) > 1 else None
        sid = str(uuid.uuid4())
        salt = os.urandom(20)
        await self._emit(
            make_event(
                "session_start",
                source_ip=src_ip, source_port=src_port, dest_port=self._port,
                protocol="mysql", session_id=sid, payload={"service": "db"},
            )
        )
        try:
            writer.write(_packet(0, self._build_handshake(salt)))
            await writer.drain()

            try:
                login_seq, resp = await asyncio.wait_for(_read_packet(reader), timeout=8)
            except Exception:  # noqa: BLE001
                return
            username = self._parse_username(resp)
            await self._emit(
                make_event(
                    "auth_attempt",
                    source_ip=src_ip, source_port=src_port, dest_port=self._port,
                    protocol="mysql", severity="medium", session_id=sid,
                    payload={"username": username, "service": "db", "auth": "mysql_native_password"},
                )
            )

            # Accept the login so the client proceeds and reveals its queries.
            # The reply must follow the client's login packet sequence number.
            writer.write(_packet(login_seq + 1, _ok()))
            await writer.drain()

            while True:
                try:
                    cseq, pkt = await asyncio.wait_for(_read_packet(reader), timeout=30)
                except Exception:  # noqa: BLE001
                    break
                if not pkt:
                    break
                cmd = pkt[0]
                if cmd == COM_QUIT:
                    break
                if cmd == COM_QUERY:
                    sql = pkt[1:].decode(errors="replace")
                    await self._emit(
                        make_event(
                            "command",
                            source_ip=src_ip, dest_port=self._port, protocol="mysql",
                            severity="medium", session_id=sid,
                            payload={"command": sql, "service": "db"},
                        )
                    )
                    # Plausible error: capture the query, reveal nothing.
                    writer.write(_packet(cseq + 1, _err(1142, "42000", "command denied to user")))
                    await writer.drain()
                else:
                    writer.write(_packet(cseq + 1, _ok()))
                    await writer.drain()
        except Exception as exc:  # noqa: BLE001
            log.warning("mysql handler error: %s", exc)
        finally:
            await self._emit(
                make_event("session_end", source_ip=src_ip, protocol="mysql", session_id=sid)
            )
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
