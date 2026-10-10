"""Agent-facing API contracts (see docs/DESIGN.md §6.2).

These are fronted by the disguised /assets/v3/* paths in Nginx; the agent never
sees honeypot/c2-looking names.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class EnrollRequest(BaseModel):
    enroll_token: str
    meta: dict = Field(default_factory=dict)


class ConfigPayload(BaseModel):
    config: dict
    config_etag: str


class EnrollResponse(ConfigPayload):
    agent_id: uuid.UUID
    agent_key: str


class EventIn(BaseModel):
    dedup_key: str | None = None
    event_type: str
    occurred_at: datetime
    source_ip: str | None = None
    source_port: int | None = None
    dest_port: int | None = None
    protocol: str | None = None
    severity: str = "info"
    session_id: uuid.UUID | None = None
    payload: dict = Field(default_factory=dict)


class BeaconIn(BaseModel):
    uptime_s: int | None = None
    hp_status: str | None = None


class TelemetryIn(BaseModel):
    sent_at: datetime | None = None
    beacon: BeaconIn | None = None
    events: list[EventIn] = Field(default_factory=list)


class TelemetryResponse(BaseModel):
    accepted: int
    next_poll_s: int
    config_etag: str
