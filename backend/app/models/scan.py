"""Scan model."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"), nullable=False)
    mode: Mapped[str] = mapped_column(String(32), default="deep_scan")  # deep_scan | attack
    status: Mapped[str] = mapped_column(String(32), default="pending")  # pending|running|completed|failed|cancelled
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    current_tool: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    configuration: Mapped[dict] = mapped_column(JSON, default=dict)
    error_message: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    tool_results = relationship("ToolResult", back_populates="scan", cascade="all, delete-orphan")
