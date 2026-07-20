"""Payload template schemas."""

from datetime import datetime

from pydantic import BaseModel, Field


class TemplateCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    category: str = Field(default="custom", max_length=64)
    description: str | None = None
    method: str = Field(default="GET", pattern="^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$")
    path_template: str = Field(default="/", max_length=1024)
    headers: dict[str, str] = Field(default_factory=dict)
    body_template: str | None = None
    payloads: list[str] = Field(default_factory=list)
    match_status: list[int] = Field(default_factory=list)
    match_body_contains: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class TemplateUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    category: str | None = None
    description: str | None = None
    method: str | None = Field(
        default=None, pattern="^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$"
    )
    path_template: str | None = None
    headers: dict[str, str] | None = None
    body_template: str | None = None
    payloads: list[str] | None = None
    match_status: list[int] | None = None
    match_body_contains: list[str] | None = None
    tags: list[str] | None = None


class TemplateOut(BaseModel):
    id: str
    name: str
    category: str
    description: str | None
    method: str
    path_template: str
    headers: dict
    body_template: str | None
    payloads: list
    match_status: list
    match_body_contains: list
    tags: list
    created_by: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class TemplateRunRequest(BaseModel):
    target: str = Field(min_length=1, max_length=512)
    auth_header: str | None = None
    authorized: bool = False
    timeout: int = Field(default=15, ge=5, le=120)
    max_payloads: int = Field(default=20, ge=1, le=100)


class TemplateHit(BaseModel):
    payload: str
    url: str
    status_code: int
    matched: bool
    body_snippet: str | None = None
    poc_curl: str | None = None


class TemplateRunResult(BaseModel):
    template_id: str
    template_name: str
    target: str
    hits: list[TemplateHit]
    total_tested: int
    matched_count: int
