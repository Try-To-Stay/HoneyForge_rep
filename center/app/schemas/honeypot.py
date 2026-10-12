from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class HoneypotCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    profile_id: uuid.UUID
    host_label: str | None = Field(default=None, max_length=128)


class HoneypotOut(BaseModel):
    id: uuid.UUID
    name: str
    profile_id: uuid.UUID
    status: str
    last_seen_at: datetime | None
    host_label: str | None
    exposure_score: int = 0
    auto_deployed: bool = False
    created_at: datetime

    model_config = {"from_attributes": True}


class HoneypotCreated(BaseModel):
    """Returned once on registration — the enroll_token is shown a single time."""

    honeypot: HoneypotOut
    enroll_token: str
