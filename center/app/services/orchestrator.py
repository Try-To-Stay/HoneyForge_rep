"""One-button honeypot deployment (Bonus FR-C6).

Launches a honeypot-host container from the agent image on the honeynet,
passing a fresh enroll token so it self-enrolls. Lab-only: requires the Docker
socket mounted into the center. Blocking Docker calls run in a thread.
"""
from __future__ import annotations

import asyncio

from app.config import get_settings

settings = get_settings()


def _deploy_sync(honeypot_id: str, enroll_token: str, name: str) -> str:
    import docker  # imported lazily so the center runs without the socket

    client = docker.from_env()
    container = client.containers.run(
        image=settings.orchestrator_image,
        detach=True,
        name=name,
        environment={
            "HONEYFORGE_BASE_URL": settings.orchestrator_base_url,
            "HONEYFORGE_ENROLL_TOKEN": enroll_token,
            "AGENT_TLS_VERIFY": "true" if settings.orchestrator_tls_verify else "false",
            "AGENT_BEACON_INTERVAL_S": "10",
        },
        network=settings.orchestrator_network,
        labels={"honeyforge.managed": "true", "honeyforge.honeypot_id": honeypot_id},
        restart_policy={"Name": "unless-stopped"},
    )
    return container.id[:12]


async def deploy_honeypot(honeypot_id: str, enroll_token: str) -> str:
    name = f"hf-deployed-{honeypot_id[:8]}"
    return await asyncio.to_thread(_deploy_sync, honeypot_id, enroll_token, name)
