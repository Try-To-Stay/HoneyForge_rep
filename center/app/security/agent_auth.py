"""Agent authentication.

On Must the agent presents its opaque key in an innocuous-looking header
(X-Request-Id) over TLS; the center matches its SHA-256 against the stored
agent_key_hash. mTLS + pinning + key rotation is Bonus (MASK-7).
"""
from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select

from app.db.models import Honeypot
from app.security.deps import DbSession
from app.security.passwords import hash_token

AGENT_KEY_HEADER = "X-Request-Id"


async def get_agent_honeypot(
    db: DbSession,
    x_request_id: Annotated[str | None, Header(alias=AGENT_KEY_HEADER)] = None,
) -> Honeypot:
    if not x_request_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    key_hash = hash_token(x_request_id)
    result = await db.execute(select(Honeypot).where(Honeypot.agent_key_hash == key_hash))
    hp = result.scalar_one_or_none()
    if hp is None:
        # Return 404, not 401 — don't reveal that this is an auth-gated endpoint.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    return hp


AgentHoneypot = Annotated[Honeypot, Depends(get_agent_honeypot)]
