"""Target model."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    type: Mapped[str] = mapped_column(String(32), default="web")  # web | api | android_backend
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
