"""Parse curl commands and execute API-mode HTTP requests."""

from __future__ import annotations

import json
import re
import shlex
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from app.schemas.api_mode import ApiRequestBody, ApiResponseOut, ParsedCurl

_MAX_BODY = 200_000


def parse_curl(curl_text: str) -> ParsedCurl:
    """Best-effort curl → structured request. Supports common -X/-H/-d/-data flags."""
    text = curl_text.strip()
    if text.startswith("curl"):
        text = text[4:].lstrip()
    # Normalize line continuations
    text = text.replace("\\\n", " ").replace("\\\r\n", " ")

    try:
        tokens = shlex.split(text, posix=True)
    except ValueError as exc:
        raise ValueError(f"Could not parse curl command: {exc}") from exc

    method = "GET"
    url: str | None = None
    headers: dict[str, str] = {}
    body: str | None = None
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-X", "--request") and i + 1 < len(tokens):
            method = tokens[i + 1].upper()
            i += 2
            continue
        if tok in ("-H", "--header") and i + 1 < len(tokens):
            raw = tokens[i + 1]
            if ":" in raw:
                k, v = raw.split(":", 1)
                headers[k.strip()] = v.strip()
            i += 2
            continue
        if tok in (
            "-d",
            "--data",
            "--data-raw",
            "--data-binary",
            "--data-urlencode",
        ) and i + 1 < len(tokens):
            body = tokens[i + 1]
            if method == "GET":
                method = "POST"
            i += 2
            continue
        if tok in ("-u", "--user") and i + 1 < len(tokens):
            import base64

            creds = base64.b64encode(tokens[i + 1].encode()).decode()
            headers["Authorization"] = f"Basic {creds}"
            i += 2
            continue
        if tok in ("-A", "--user-agent") and i + 1 < len(tokens):
            headers["User-Agent"] = tokens[i + 1]
            i += 2
            continue
        if tok.startswith("-"):
            # skip unknown short/long flags (optionally with value)
            if tok in ("-k", "--insecure", "-s", "--silent", "-L", "--location", "-i", "--include", "-v", "--verbose", "-G", "--get"):
                if tok in ("-G", "--get"):
                    method = "GET"
                i += 1
                continue
            # flag that might take a value we don't care about
            if i + 1 < len(tokens) and not tokens[i + 1].startswith("-") and not _looks_like_url(tokens[i + 1]):
                i += 2
            else:
                i += 1
            continue
        if _looks_like_url(tok) or tok.startswith("/") or "://" in tok:
            url = tok.strip("'\"")
            i += 1
            continue
        i += 1

    if not url:
        # Sometimes URL is the only positional after options
        raise ValueError("No URL found in curl command")

    if not urlparse(url).scheme:
        url = "https://" + url

    return ParsedCurl(method=method, url=url, headers=headers, body=body)


def _looks_like_url(s: str) -> bool:
    return bool(re.match(r"^(https?://|//)", s, re.I)) or (
        "." in s and " " not in s and not s.startswith("-")
    )


def build_poc_curl(req: ApiRequestBody) -> str:
    parts = ["curl", "-sS", "-X", req.method]
    for k, v in (req.headers or {}).items():
        parts.extend(["-H", f"{k}: {v}"])
    if req.body:
        parts.extend(["--data-raw", req.body])
    parts.append(req.url)
    return " ".join(shlex.quote(p) for p in parts)


async def execute_request(req: ApiRequestBody) -> ApiResponseOut:
    headers = dict(req.headers or {})
    start = time.perf_counter()
    truncated = False
    async with httpx.AsyncClient(
        follow_redirects=req.follow_redirects,
        timeout=req.timeout,
        verify=True,
    ) as client:
        response = await client.request(
            req.method,
            req.url,
            headers=headers,
            content=req.body.encode() if req.body else None,
        )
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    body = response.text
    if len(body) > _MAX_BODY:
        body = body[:_MAX_BODY]
        truncated = True

    resp_headers = {k: v for k, v in response.headers.items()}
    return ApiResponseOut(
        method=req.method,
        url=str(response.url),
        status_code=response.status_code,
        elapsed_ms=elapsed_ms,
        response_headers=resp_headers,
        body=body,
        body_truncated=truncated,
        request_headers=headers,
        poc_curl=build_poc_curl(req),
    )


def preview_json(obj: Any) -> str:
    try:
        return json.dumps(obj, indent=2)[:5000]
    except (TypeError, ValueError):
        return str(obj)[:5000]
