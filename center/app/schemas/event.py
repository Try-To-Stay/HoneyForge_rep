from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, field_validator


class EventOut(BaseModel):
    id: int
    honeypot_id: uuid.UUID
    event_type: str
    source_ip: str | None

    @field_validator("source_ip", mode="before")
    @classmethod
    def _ip_to_str(cls, v):
        return str(v) if v is not None else None

    source_port: int | None
    dest_port: int | None
    protocol: str | None
    severity: str
    technique: str | None = None
    session_id: uuid.UUID | None
    payload: dict
    occurred_at: datetime
    received_at: datetime

    model_config = {"from_attributes": True}


class EventPage(BaseModel):
    items: list[EventOut]
    next_cursor: int | None
