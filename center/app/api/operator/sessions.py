"""Interactive session detail — credentials and commands (Medium honeypot)."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from app.db.models import AuthAttempt, Event, Session
from app.schemas.event import EventOut
from app.schemas.session import AuthAttemptOut, SessionDetail
from app.security.deps import CurrentOperator, DbSession

router = APIRouter(prefix="/sessions", tags=["sessions"])


@router.get("/{session_id}", response_model=SessionDetail)
async def get_session(session_id: uuid.UUID, current: CurrentOperator, db: DbSession):
    sess = await db.get(Session, session_id)
    if sess is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    attempts = (
        await db.execute(
            select(AuthAttempt)
            .where(AuthAttempt.session_id == session_id)
            .order_by(AuthAttempt.occurred_at)
        )
    ).scalars().all()

    commands = (
        await db.execute(
            select(Event)
            .where(Event.session_id == session_id, Event.event_type == "command")
            .order_by(Event.occurred_at)
        )
    ).scalars().all()

    return SessionDetail(
        id=sess.id,
        honeypot_id=sess.honeypot_id,
        service=sess.service,
        source_ip=sess.source_ip,
        started_at=sess.started_at,
        ended_at=sess.ended_at,
        auth_attempts=[AuthAttemptOut.model_validate(a) for a in attempts],
        commands=[EventOut.model_validate(c) for c in commands],
    )
