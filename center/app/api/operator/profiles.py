"""Honeypot profile CRUD (FR-C1)."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.db.models import Profile
from app.schemas.profile import ProfileCreate, ProfileOut, ProfileUpdate
from app.security.deps import CurrentOperator, DbSession
from app.services import audit

router = APIRouter(prefix="/profiles", tags=["profiles"])


async def _get_or_404(db: DbSession, profile_id: uuid.UUID) -> Profile:
    profile = await db.get(Profile, profile_id)
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found")
    return profile


@router.get("", response_model=list[ProfileOut])
async def list_profiles(current: CurrentOperator, db: DbSession):
    result = await db.execute(select(Profile).order_by(Profile.created_at.desc()))
    return list(result.scalars().all())


@router.post("", response_model=ProfileOut, status_code=status.HTTP_201_CREATED)
async def create_profile(body: ProfileCreate, current: CurrentOperator, db: DbSession):
    profile = Profile(
        name=body.name, level=body.level, config=body.config, created_by=current.id
    )
    db.add(profile)
    await db.flush()
    await audit.record(
        db, operator_id=current.id, action="profile.create", target=str(profile.id)
    )
    await db.commit()
    await db.refresh(profile)
    return profile


@router.get("/{profile_id}", response_model=ProfileOut)
async def get_profile(profile_id: uuid.UUID, current: CurrentOperator, db: DbSession):
    return await _get_or_404(db, profile_id)


@router.put("/{profile_id}", response_model=ProfileOut)
async def update_profile(
    profile_id: uuid.UUID, body: ProfileUpdate, current: CurrentOperator, db: DbSession
):
    profile = await _get_or_404(db, profile_id)
    data = body.model_dump(exclude_unset=True)
    for field, value in data.items():
        setattr(profile, field, value)
    await audit.record(
        db, operator_id=current.id, action="profile.update", target=str(profile.id)
    )
    await db.commit()
    await db.refresh(profile)
    return profile


@router.delete("/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_profile(profile_id: uuid.UUID, current: CurrentOperator, db: DbSession):
    profile = await _get_or_404(db, profile_id)
    await db.delete(profile)
    await audit.record(
        db, operator_id=current.id, action="profile.delete", target=str(profile_id)
    )
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Profile is still referenced by one or more honeypots",
        )
