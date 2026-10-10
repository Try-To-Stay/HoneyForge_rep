"""Aggregate operator (mgmt) API under /api/v1."""
from __future__ import annotations

from fastapi import APIRouter

from app.api.operator import auth, honeypots, profiles

operator_router = APIRouter(prefix="/api/v1")
operator_router.include_router(auth.router)
operator_router.include_router(auth.me_router)
operator_router.include_router(profiles.router)
operator_router.include_router(honeypots.router)
