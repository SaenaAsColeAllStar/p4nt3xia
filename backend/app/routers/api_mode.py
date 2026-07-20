"""API / curl mode — paste curl or fire structured HTTP against authorized targets."""

from fastapi import APIRouter, HTTPException

from app.deps import RequireOperator, RequireViewer
from app.schemas.api_mode import (
    ApiRequestBody,
    ApiResponseOut,
    CurlParseRequest,
    ParsedCurl,
)
from app.services import api_mode as api_mode_svc

router = APIRouter(prefix="/api-mode", tags=["api-mode"])


@router.post("/parse", response_model=ParsedCurl)
def parse_curl(payload: CurlParseRequest, _user: RequireViewer) -> ParsedCurl:
    try:
        return api_mode_svc.parse_curl(payload.curl)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/request", response_model=ApiResponseOut)
async def execute_request(
    payload: ApiRequestBody,
    _user: RequireOperator,
) -> ApiResponseOut:
    # Soft authorization gate for write/mutative probing
    if payload.method.upper() not in ("GET", "HEAD", "OPTIONS") and not payload.authorized:
        raise HTTPException(
            status_code=400,
            detail="authorized=true required for non-GET API mode requests",
        )
    try:
        return await api_mode_svc.execute_request(payload)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Request failed: {exc}") from exc


@router.post("/from-curl", response_model=ApiResponseOut)
async def execute_from_curl(
    payload: CurlParseRequest,
    authorized: bool = False,
    timeout: int = 30,
    _user: RequireOperator = None,
) -> ApiResponseOut:
    try:
        parsed = api_mode_svc.parse_curl(payload.curl)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    body = ApiRequestBody(
        method=parsed.method,
        url=parsed.url,
        headers=parsed.headers,
        body=parsed.body,
        timeout=timeout,
        authorized=authorized,
    )
    if body.method.upper() not in ("GET", "HEAD", "OPTIONS") and not authorized:
        raise HTTPException(
            status_code=400,
            detail="authorized=true required for non-GET curl execution",
        )
    try:
        return await api_mode_svc.execute_request(body)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Request failed: {exc}") from exc
