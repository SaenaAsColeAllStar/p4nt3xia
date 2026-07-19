"""Target schemas."""

from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class TargetCreate(BaseModel):
    value: str = Field(..., min_length=1, max_length=512)
    type: str = Field(default="web", pattern="^(web|api|android_backend)$")
    tags: list[str] = Field(default_factory=list)
    notes: str | None = None

    @field_validator("value")
    @classmethod
    def normalize_value(cls, v: str) -> str:
        return v.strip()


class TargetOut(BaseModel):
    id: str
    value: str
    type: str
    created_at: datetime
    tags: list[str] = []
    notes: str | None = None

    model_config = {"from_attributes": True}
