"""Durable local event buffer (FR-A4).

Events are persisted to SQLite the moment the honeypot produces them, so a
loss of connectivity to the center never loses events — they are re-sent once
the channel is back. dedup_key on the center side makes re-delivery idempotent.
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS buffered_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class Buffer:
    def __init__(self, path: str):
        self._path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path)
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    # --- sync inner ops, wrapped in threads below ---
    def _enqueue(self, event: dict) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO buffered_events (payload) VALUES (?)", (json.dumps(event),)
            )

    def _pending(self, limit: int) -> list[tuple[int, dict]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, payload FROM buffered_events ORDER BY id LIMIT ?", (limit,)
            ).fetchall()
        return [(r[0], json.loads(r[1])) for r in rows]

    def _delete(self, ids: list[int]) -> None:
        if not ids:
            return
        with self._connect() as conn:
            conn.executemany("DELETE FROM buffered_events WHERE id = ?", [(i,) for i in ids])

    def _count(self) -> int:
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM buffered_events").fetchone()[0]

    # --- async wrappers ---
    async def enqueue(self, event: dict) -> None:
        await asyncio.to_thread(self._enqueue, event)

    async def pending(self, limit: int) -> list[tuple[int, dict]]:
        return await asyncio.to_thread(self._pending, limit)

    async def delete(self, ids: list[int]) -> None:
        await asyncio.to_thread(self._delete, ids)

    async def count(self) -> int:
        return await asyncio.to_thread(self._count)
