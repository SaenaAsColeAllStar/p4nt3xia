"""Finding model."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="info")  # info|low|medium|high|critical
    finding_type: Mapped[str] = mapped_column(String(64), default="info")
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cve_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    poc_request: Mapped[str | None] = mapped_column(Text, nullable=True)
    poc_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    poc_curl: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[list] = mapped_column(JSON, default=list)
    raw_data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scan = relationship("Scan", back_populates="findings")
