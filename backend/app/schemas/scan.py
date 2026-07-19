"""Scan schemas."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.schemas.finding import FindingOut
from app.schemas.target import TargetOut


class DeepScanOptions(BaseModel):
    subdomain_enum: bool = True
    port_scan: bool = True
    directory_fuzz: bool = True
    tech_detect: bool = True
    safe_vuln_scan: bool = True
    crawl: bool = True
    threads: int = Field(default=3, ge=1, le=50)
    timeout: int = Field(default=30, ge=5, le=600)


class DeepScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=512, description="URL, domain, or IP")
    target_type: str = Field(default="web", pattern="^(web|api|android_backend)$")
    options: DeepScanOptions = Field(default_factory=DeepScanOptions)

    @field_validator("target")
    @classmethod
    def normalize_target(cls, v: str) -> str:
        return v.strip()


class AttackModeOptions(BaseModel):
    sql_injection: bool = True
    xss: bool = True
    nuclei_exploit: bool = True
    threads: int = Field(default=3, ge=1, le=50)
    timeout: int = Field(default=60, ge=10, le=900)
    delay_ms: int = Field(default=0, ge=0, le=10_000)
    sqlmap_level: int = Field(default=2, ge=1, le=5)
    sqlmap_risk: int = Field(default=2, ge=1, le=3)
    authorized: bool = Field(
        default=False,
        description="Must be true — explicit authorization confirmation",
    )


class AttackScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=512)
    target_type: str = Field(default="web", pattern="^(web|api|android_backend)$")
    auth_header: str | None = Field(
        default=None,
        max_length=2048,
        description="Optional Authorization header value (e.g. Bearer …)",
    )
    options: AttackModeOptions = Field(default_factory=AttackModeOptions)

    @field_validator("target")
    @classmethod
    def normalize_target(cls, v: str) -> str:
        return v.strip()

    @field_validator("auth_header")
    @classmethod
    def normalize_auth(cls, v: str | None) -> str | None:
        if v is None:
            return None
        stripped = v.strip()
        return stripped or None


class ToolResultOut(BaseModel):
    id: str
    scan_id: str
    tool_name: str
    command: str
    stdout: str | None = None
    stderr: str | None = None
    exit_code: int | None = None
    duration_ms: int | None = None
    status: str
    parsed_output: dict = Field(default_factory=dict)
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: str
    target_id: str
    mode: str
    status: str
    progress: float
    current_tool: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    configuration: dict = Field(default_factory=dict)
    error_message: str | None = None
    target: TargetOut | None = None

    model_config = {"from_attributes": True}


class ScanWithDetails(ScanOut):
    findings: list[FindingOut] = Field(default_factory=list)
    tool_results: list[ToolResultOut] = Field(default_factory=list)


class ScanProgressEvent(BaseModel):
    scan_id: str
    status: str
    progress: float
    current_tool: str | None = None
    message: str = ""
    finding: FindingOut | None = None
    tool_result: dict[str, Any] | None = None


class DashboardStats(BaseModel):
    total_scans: int = 0
    active_targets: int = 0
    vulnerabilities_found: int = 0
    running_scans: int = 0
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    recent_scans: list[ScanOut] = Field(default_factory=list)
