from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, field_validator

from app.schemas.event import EventOut


class AuthAttemptOut(BaseModel):
    id: int
    username: str | None
    password_preview: str | None
    success: bool
    occurred_at: datetime

    model_config = {"from_attributes": True}


class SessionDetail(BaseModel):
    id: uuid.UUID
    honeypot_id: uuid.UUID
    service: str
    source_ip: str | None
    started_at: datetime
    ended_at: datetime | None
    auth_attempts: list[AuthAttemptOut]
    commands: list[EventOut]

    model_config = {"from_attributes": True}

    @field_validator("source_ip", mode="before")
    @classmethod
    def _ip_to_str(cls, v):
        return str(v) if v is not None else None
