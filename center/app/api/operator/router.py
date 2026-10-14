"""Aggregate operator (mgmt) API under /api/v1."""
from __future__ import annotations

from fastapi import APIRouter

from app.api.operator import (
    alerts,
    artifacts,
    auth,
    events,
    export,
    honeypots,
    intel,
    profiles,
    sessions,
    stats,
)

operator_router = APIRouter(prefix="/api/v1")
operator_router.include_router(auth.router)
operator_router.include_router(auth.me_router)
operator_router.include_router(profiles.router)
operator_router.include_router(honeypots.router)
operator_router.include_router(events.router)
operator_router.include_router(sessions.router)
operator_router.include_router(stats.router)
operator_router.include_router(alerts.router)
operator_router.include_router(export.router)
operator_router.include_router(intel.router)
operator_router.include_router(artifacts.router)
