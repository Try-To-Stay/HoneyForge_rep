from __future__ import annotations

import uuid

from pydantic import BaseModel


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class AccessToken(BaseModel):
    access_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class OperatorOut(BaseModel):
    id: uuid.UUID
    username: str
    role: str

    model_config = {"from_attributes": True}
