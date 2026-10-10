"""HoneyForge Control API — application entrypoint.

Sprint 0 scope: app skeleton with a /healthz that verifies PostgreSQL and
Redis connectivity. Routers for operator/agent APIs and realtime are added
from Sprint 1 onward (see docs/DESIGN.md §6).
"""
from __future__ import annotations

from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api.agent.router import router as agent_router
from app.api.operator.router import operator_router
from app.config import get_settings
from app.db.base import engine

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.redis = aioredis.from_url(settings.redis_dsn, decode_responses=True)
    try:
        yield
    finally:
        await app.state.redis.aclose()
        await engine.dispose()


app = FastAPI(
    title="HoneyForge Control API",
    version="0.1.0",
    summary="Centralized honeypot management platform (MVP)",
    lifespan=lifespan,
)


app.include_router(operator_router)
app.include_router(agent_router)


@app.get("/healthz", tags=["ops"])
async def healthz():
    """Liveness/readiness: checks DB and Redis. Returns 503 if a dependency is down."""
    checks: dict[str, str] = {}
    healthy = True

    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["postgres"] = "ok"
    except Exception as exc:  # noqa: BLE001 - report, don't crash the probe
        checks["postgres"] = f"error: {exc.__class__.__name__}"
        healthy = False

    try:
        await app.state.redis.ping()
        checks["redis"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["redis"] = f"error: {exc.__class__.__name__}"
        healthy = False

    status = "ok" if healthy else "degraded"
    return JSONResponse(
        status_code=200 if healthy else 503,
        content={"status": status, "checks": checks},
    )


@app.get("/", tags=["ops"])
async def root():
    return {"service": "honeyforge-center", "version": app.version}
