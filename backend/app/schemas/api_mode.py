"""API (curl) mode schemas."""

from pydantic import BaseModel, Field


class CurlParseRequest(BaseModel):
    curl: str = Field(min_length=4, max_length=50_000)


class ApiRequestBody(BaseModel):
    """Structured HTTP request — same shape produced by curl parsing."""

    method: str = Field(default="GET", pattern="^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$")
    url: str = Field(min_length=1, max_length=4096)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    timeout: int = Field(default=30, ge=5, le=120)
    follow_redirects: bool = True
    authorized: bool = False  # required when used as attack probe


class ParsedCurl(BaseModel):
    method: str
    url: str
    headers: dict[str, str]
    body: str | None = None


class ApiResponseOut(BaseModel):
    method: str
    url: str
    status_code: int
    elapsed_ms: int
    response_headers: dict[str, str]
    body: str
    body_truncated: bool = False
    request_headers: dict[str, str]
    poc_curl: str
