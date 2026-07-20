"""Run custom payload templates against a target (authorized testing only)."""

from __future__ import annotations

import shlex
from urllib.parse import urljoin, urlparse

import httpx

from app.models.payload_template import PayloadTemplate
from app.schemas.template import TemplateHit, TemplateRunRequest, TemplateRunResult


def _base_url(target: str) -> str:
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    parsed = urlparse(t)
    return f"{parsed.scheme}://{parsed.netloc}"


def _render(s: str, payload: str, path: str = "") -> str:
    return (
        s.replace("{{payload}}", payload)
        .replace("{{PAYLOAD}}", payload)
        .replace("{{path}}", path)
    )


def _poc_curl(method: str, url: str, headers: dict[str, str], body: str | None) -> str:
    parts = ["curl", "-sS", "-X", method]
    for k, v in headers.items():
        parts.extend(["-H", f"{k}: {v}"])
    if body:
        parts.extend(["--data-raw", body])
    parts.append(url)
    return " ".join(shlex.quote(p) for p in parts)


async def run_template(
    template: PayloadTemplate, req: TemplateRunRequest
) -> TemplateRunResult:
    if not req.authorized:
        raise ValueError(
            "Authorization confirmation required. Set authorized=true only for "
            "systems you are permitted to test."
        )

    base = _base_url(req.target)
    payloads = list(template.payloads or [])[: req.max_payloads]
    if not payloads:
        payloads = [""]

    headers_base = dict(template.headers or {})
    if req.auth_header:
        headers_base["Authorization"] = req.auth_header

    hits: list[TemplateHit] = []
    matched_count = 0

    async with httpx.AsyncClient(follow_redirects=True, timeout=req.timeout) as client:
        for payload in payloads:
            path = _render(template.path_template or "/", payload)
            if path.startswith("http://") or path.startswith("https://"):
                url = path
            else:
                url = urljoin(base + "/", path.lstrip("/"))

            headers = {
                k: _render(v, payload) for k, v in headers_base.items()
            }
            body = None
            if template.body_template:
                body = _render(template.body_template, payload)

            try:
                response = await client.request(
                    template.method or "GET",
                    url,
                    headers=headers,
                    content=body.encode() if body else None,
                )
                status = response.status_code
                text = response.text[:8000]
            except Exception as exc:
                hits.append(
                    TemplateHit(
                        payload=payload,
                        url=url,
                        status_code=0,
                        matched=False,
                        body_snippet=str(exc)[:500],
                        poc_curl=_poc_curl(template.method or "GET", url, headers, body),
                    )
                )
                continue

            matched = False
            match_status = template.match_status or []
            match_contains = template.match_body_contains or []
            if match_status and status in match_status:
                matched = True
            if match_contains and any(c in text for c in match_contains):
                matched = True
            # If no matchers configured, treat 2xx/3xx/5xx quirks as informative hits
            if not match_status and not match_contains:
                matched = status >= 200

            if matched:
                matched_count += 1

            hits.append(
                TemplateHit(
                    payload=payload,
                    url=url,
                    status_code=status,
                    matched=matched,
                    body_snippet=text[:500] if matched else text[:200],
                    poc_curl=_poc_curl(template.method or "GET", url, headers, body),
                )
            )

    return TemplateRunResult(
        template_id=template.id,
        template_name=template.name,
        target=req.target,
        hits=hits,
        total_tested=len(payloads),
        matched_count=matched_count,
    )
