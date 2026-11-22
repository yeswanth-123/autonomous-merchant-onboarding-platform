from datetime import datetime

from sqlalchemy import (JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer,
                        String, Text, UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column

from . import clock
from .db import Base


def _utc_now():
    return clock.now()


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(300), default="")
    role: Mapped[str] = mapped_column(String(12), default="merchant")
    full_name: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    consented_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)


class UserSession(Base):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    csrf: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)


class Application(Base):
    __tablename__ = "applications"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    external_ref: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    docs_purged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    anonymised_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    state: Mapped[str] = mapped_column(String(32), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    data_version: Mapped[int] = mapped_column(Integer, default=1)
    business_type: Mapped[str] = mapped_column(String(32), default="company")
    legal_name_norm: Mapped[str] = mapped_column(String(200), default="")
    pincode: Mapped[str] = mapped_column(String(10), default="")
    payout_hold: Mapped[bool] = mapped_column(Boolean, default=False)
    flags: Mapped[dict] = mapped_column(JSON, default=dict)
    missing_info: Mapped[list] = mapped_column(JSON, default=list)
    scenarios: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    state_entered_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)


class ApplicationVersion(Base):
    __tablename__ = "application_versions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    data_version: Mapped[int] = mapped_column(Integer)
    form_data_enc: Mapped[str] = mapped_column(Text)
    form_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    created_by: Mapped[str] = mapped_column(String(64), default="merchant")
    __table_args__ = (UniqueConstraint("application_id", "data_version"),)


class Document(Base):
    __tablename__ = "documents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    data_version: Mapped[int] = mapped_column(Integer)
    doc_type: Mapped[str] = mapped_column(String(16))
    filename: Mapped[str | None] = mapped_column(String(200), nullable=True)
    storage_path: Mapped[str | None] = mapped_column(String(400), nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(16), nullable=True)
    purged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    payload_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    sha256: Mapped[str] = mapped_column(String(64), default="")
    quality_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)


class ExtractedField(Base):
    __tablename__ = "extracted_fields"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    data_version: Mapped[int] = mapped_column(Integer)
    document_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    doc_type: Mapped[str] = mapped_column(String(16), default="FORM")
    field_name: Mapped[str] = mapped_column(String(64))
    value_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    value_masked: Mapped[str | None] = mapped_column(String(200), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    source: Mapped[str] = mapped_column(String(16), default="form")
    validation_status: Mapped[str] = mapped_column(String(16), default="VALID")
    detail: Mapped[str] = mapped_column(Text, default="")


class Verification(Base):
    __tablename__ = "verifications"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    check_type: Mapped[str] = mapped_column(String(8))
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(12), default="REQUESTED")
    request_id: Mapped[str] = mapped_column(String(40), unique=True)
    idempotency_key: Mapped[str] = mapped_column(String(160))
    input_hash: Mapped[str] = mapped_column(String(64))
    data_version: Mapped[int] = mapped_column(Integer)
    requested_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    deadline_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    reason_code: Mapped[str | None] = mapped_column(String(48), nullable=True)
    result_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    __table_args__ = (Index("ix_ver_app_check", "application_id", "check_type"),)


class ProviderEvent(Base):
    __tablename__ = "provider_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    provider: Mapped[str] = mapped_column(String(16))
    event_id: Mapped[str] = mapped_column(String(64))
    request_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    raw_enc: Mapped[str] = mapped_column(Text, default="")
    disposition: Mapped[str] = mapped_column(String(16), default="APPLIED")
    __table_args__ = (UniqueConstraint("provider", "event_id", name="uq_provider_event"),)


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    type: Mapped[str] = mapped_column(String(32), index=True)
    application_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    run_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    status: Mapped[str] = mapped_column(String(10), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=5)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(120), unique=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    application_id: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    actor: Mapped[str] = mapped_column(String(64))
    event_type: Mapped[str] = mapped_column(String(48))
    from_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)


class ReviewTask(Base):
    __tablename__ = "review_tasks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    reason_code: Mapped[str] = mapped_column(String(48))
    priority: Mapped[int] = mapped_column(Integer, default=2)
    status: Mapped[str] = mapped_column(String(10), default="open")
    assignee: Mapped[str | None] = mapped_column(String(64), nullable=True)
    opened_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolution: Mapped[str | None] = mapped_column(String(32), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    context: Mapped[dict] = mapped_column(JSON, default=dict)


class IdentityKey(Base):
    __tablename__ = "identity_keys"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), index=True)
    kind: Mapped[str] = mapped_column(String(12))
    key_hash: Mapped[str] = mapped_column(String(64), index=True)
    __table_args__ = (UniqueConstraint("application_id", "kind", "key_hash"),)


class Merchant(Base):
    __tablename__ = "merchants"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    merchant_id: Mapped[str] = mapped_column(String(32), unique=True)
    application_id: Mapped[str] = mapped_column(ForeignKey("applications.id"), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
