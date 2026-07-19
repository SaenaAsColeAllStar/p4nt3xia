"""Finding schemas."""

from datetime import datetime

from pydantic import BaseModel, Field


class FindingOut(BaseModel):
    id: str
    scan_id: str
    title: str
    severity: str
    finding_type: str = "info"
    cvss_score: float | None = None
    cve_id: str | None = None
    description: str | None = None
    poc_request: str | None = None
    poc_response: str | None = None
    poc_curl: str | None = None
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)
    raw_data: dict = Field(default_factory=dict)
    created_at: datetime

    model_config = {"from_attributes": True}
