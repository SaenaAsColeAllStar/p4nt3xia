"""Custom payload template model."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PayloadTemplate(Base):
    __tablename__ = "payload_templates"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    category: Mapped[str] = mapped_column(
        String(64), default="custom"
    )  # xss|sqli|lfi|cmdi|ssrf|idor|header|custom
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    method: Mapped[str] = mapped_column(String(16), default="GET")
    path_template: Mapped[str] = mapped_column(
        String(1024), default="/{{path}}"
    )  # may include {{payload}}
    headers: Mapped[dict] = mapped_column(JSON, default=dict)
    body_template: Mapped[str | None] = mapped_column(Text, nullable=True)
    payloads: Mapped[list] = mapped_column(JSON, default=list)  # list of payload strings
    match_status: Mapped[list] = mapped_column(JSON, default=list)  # optional status codes
    match_body_contains: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    created_by: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )
