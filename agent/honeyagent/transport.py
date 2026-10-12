"""HTTPS transport to the disguised collector (MASK-1/MASK-2, and MASK-7 mTLS).

Bootstrap (enroll) uses a plain client. Once the center issues a client cert,
the transport is rebuilt to pin the CA and present the client cert on every
request (mutual TLS). Rotation rebuilds it again with the fresh cert.
"""
from __future__ import annotations

import os

import httpx

from honeyagent.config import AgentConfig

AGENT_KEY_HEADER = "X-Request-Id"


class Transport:
    def __init__(self, cfg: AgentConfig):
        self._cfg = cfg
        self._client = self._build()

    def _build(self) -> httpx.AsyncClient:
        verify: object = self._cfg.tls_verify
        cert = None
        if (
            self._cfg.mtls_enabled
            and os.path.exists(self._cfg.ca_path)
            and os.path.exists(self._cfg.client_cert_path)
            and os.path.exists(self._cfg.client_key_path)
        ):
            # Pin the CA (not system trust) and present the client cert.
            verify = self._cfg.ca_path
            cert = (self._cfg.client_cert_path, self._cfg.client_key_path)
        return httpx.AsyncClient(
            base_url=self._cfg.base_url,
            verify=verify,
            cert=cert,
            timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0 (compatible; AssetSync/3.1)"},
        )

    async def rebuild(self) -> None:
        """Recreate the client (e.g. after certs are written or rotated)."""
        old = self._client
        self._client = self._build()
        await old.aclose()

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

    async def rotate(self, agent_key: str) -> dict:
        resp = await self._client.post(
            self._cfg.path_renew, headers={AGENT_KEY_HEADER: agent_key}
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
