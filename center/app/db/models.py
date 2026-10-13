"""SQLAlchemy ORM models — HoneyForge schema (see docs/DESIGN.md §5)."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

# All timestamps are timezone-aware (stored as TIMESTAMPTZ).
TS = DateTime(timezone=True)


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


class Operator(Base):
    __tablename__ = "operators"

    id: Mapped[uuid.UUID] = _uuid_pk()
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="operator")
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), nullable=False)


class Profile(Base):
    __tablename__ = "profiles"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    level: Mapped[str] = mapped_column(String(16), nullable=False)  # low|medium|high
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("operators.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        TS, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    honeypots: Mapped[list[Honeypot]] = relationship(back_populates="profile")


class Honeypot(Base):
    __tablename__ = "honeypots"

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    profile_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("profiles.id", ondelete="RESTRICT"), nullable=False
    )
    enroll_token_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    agent_key_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    last_seen_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    host_label: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Self-defense (feature #4): exposure risk and the current rotated disguise.
    exposure_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    disguise_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Marks honeypots auto-deployed by the deception engine (feature #3).
    auto_deployed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), nullable=False)

    profile: Mapped[Profile] = relationship(back_populates="honeypots")


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = _uuid_pk()
    honeypot_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("honeypots.id", ondelete="CASCADE"), nullable=False, index=True
    )
    service: Mapped[str] = mapped_column(String(16), nullable=False)  # ssh|http|db
    source_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    started_at: Mapped[datetime] = mapped_column(TS, nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    meta: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    honeypot_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("honeypots.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source_ip: Mapped[str | None] = mapped_column(INET, nullable=True, index=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dest_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True
    )
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # MITRE ATT&CK technique id inferred at ingest (feature #2).
    technique: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    # GeoIP/ASN enrichment of the source (TЗ §7.3).
    source_country: Mapped[str | None] = mapped_column(String(2), nullable=True, index=True)
    source_asn: Mapped[str | None] = mapped_column(String(16), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(TS, nullable=False)
    received_at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), nullable=False)
    # Idempotency for buffered re-delivery (FR-A4); unique so retries don't dup.
    dedup_key: Mapped[str | None] = mapped_column(String(128), unique=True, nullable=True)


class AuthAttempt(Base):
    __tablename__ = "auth_attempts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True
    )
    honeypot_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("honeypots.id", ondelete="CASCADE"), nullable=False, index=True
    )
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    password_preview: Mapped[str | None] = mapped_column(String(64), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    occurred_at: Mapped[datetime] = mapped_column(TS, nullable=False)


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[uuid.UUID] = _uuid_pk()
    honeypot_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("honeypots.id", ondelete="CASCADE"), nullable=False
    )
    session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True
    )
    kind: Mapped[str | None] = mapped_column(String(32), nullable=True)  # pcap|session_log|upload
    path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), nullable=False)


class Honeytoken(Base):
    __tablename__ = "honeytokens"

    id: Mapped[uuid.UUID] = _uuid_pk()
    profile_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("profiles.id", ondelete="SET NULL"), nullable=True
    )
    kind: Mapped[str | None] = mapped_column(String(32), nullable=True)
    value_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    triggered_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    trigger_meta: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    honeypot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("honeypots.id", ondelete="CASCADE"), nullable=True, index=True
    )
    source_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    rule: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="high")
    message: Mapped[str] = mapped_column(String(255), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), nullable=False)


class Command(Base):
    __tablename__ = "commands"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    honeypot_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("honeypots.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action: Mapped[str] = mapped_column(String(32), nullable=False)  # stop|start|rotate_creds|refresh
    params: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")  # pending|done
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), nullable=False)
    delivered_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)
    done_at: Mapped[datetime | None] = mapped_column(TS, nullable=True)


class DeceptionAction(Base):
    __tablename__ = "deception_actions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    action: Mapped[str] = mapped_column(String(32), nullable=False)  # deploy_decoy|rotate_disguise
    source_ip: Mapped[str | None] = mapped_column(INET, nullable=True, index=True)
    honeypot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("honeypots.id", ondelete="SET NULL"), nullable=True
    )
    alert_id: Mapped[int | None] = mapped_column(
        ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True
    )
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    operator_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("operators.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TS, server_default=func.now(), nullable=False)
