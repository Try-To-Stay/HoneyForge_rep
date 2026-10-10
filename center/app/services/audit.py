"""Operator action audit trail (FR-C5)."""
from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog


async def record(
    db: AsyncSession,
    *,
    operator_id: uuid.UUID | None,
    action: str,
    target: str | None = None,
    detail: dict | None = None,
    ip: str | None = None,
) -> None:
    db.add(
        AuditLog(
            operator_id=operator_id,
            action=action,
            target=target,
            detail=detail or {},
            ip=ip,
        )
    )
    # Flush so the entry participates in the caller's transaction/commit.
    await db.flush()
