from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Level = Literal["low", "medium", "high"]


class ProfileBase(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    level: Level
    config: dict = Field(default_factory=dict)


class ProfileCreate(ProfileBase):
    pass


class ProfileUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    level: Level | None = None
    config: dict | None = None


class ProfileOut(ProfileBase):
    id: uuid.UUID
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
