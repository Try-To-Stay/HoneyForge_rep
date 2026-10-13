"""Captured file artifacts: list and download (FR-A5 uploaded files)."""
from __future__ import annotations

import os
import uuid

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select

from app.db.models import Artifact
from app.security.deps import CurrentOperator, DbSession

router = APIRouter(prefix="/artifacts", tags=["artifacts"])


@router.get("")
async def list_artifacts(current: CurrentOperator, db: DbSession):
    rows = (
        await db.execute(select(Artifact).order_by(Artifact.created_at.desc()).limit(200))
    ).scalars().all()
    return [
        {
            "id": str(a.id),
            "honeypot_id": str(a.honeypot_id),
            "session_id": str(a.session_id) if a.session_id else None,
            "kind": a.kind,
            "filename": os.path.basename(a.path or ""),
            "sha256": a.sha256,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in rows
    ]


@router.get("/{artifact_id}/download")
async def download_artifact(artifact_id: uuid.UUID, current: CurrentOperator, db: DbSession):
    a = await db.get(Artifact, artifact_id)
    if a is None or not a.path or not os.path.exists(a.path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")
    return FileResponse(a.path, filename=os.path.basename(a.path))
