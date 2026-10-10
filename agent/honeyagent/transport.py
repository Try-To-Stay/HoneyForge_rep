"""HTTPS transport to the disguised collector endpoint (MASK-1, MASK-2)."""
from __future__ import annotations

import httpx

from honeyagent.config import AgentConfig

AGENT_KEY_HEADER = "X-Request-Id"


class Transport:
    def __init__(self, cfg: AgentConfig):
        self._cfg = cfg
        self._client = httpx.AsyncClient(
            base_url=cfg.base_url,
            verify=cfg.tls_verify,
            timeout=10.0,
            # A browser-ish UA so the channel blends in with ordinary web traffic.
            headers={"User-Agent": "Mozilla/5.0 (compatible; AssetSync/3.1)"},
        )

    async def enroll(self, enroll_token: str) -> dict:
        resp = await self._client.post(
            self._cfg.path_register, json={"enroll_token": enroll_token, "meta": {}}
        )
        resp.raise_for_status()
        return resp.json()

    async def get_config(self, agent_key: str) -> dict:
        resp = await self._client.get(
            self._cfg.path_config, headers={AGENT_KEY_HEADER: agent_key}
        )
        resp.raise_for_status()
        return resp.json()

    async def send_telemetry(self, agent_key: str, beacon: dict, events: list[dict]) -> dict:
        resp = await self._client.post(
            self._cfg.path_collect,
            headers={AGENT_KEY_HEADER: agent_key},
            json={"beacon": beacon, "events": events},
        )
        resp.raise_for_status()
        return resp.json()

    async def aclose(self) -> None:
        await self._client.aclose()
