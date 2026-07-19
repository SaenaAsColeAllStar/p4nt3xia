"""Attack Mode tool wrappers — sqlmap, Dalfox, Nuclei exploit templates."""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.config import settings
from app.services.target_utils import base_url
from app.services.tool_runner import ToolRunResult, ToolRunner

logger = logging.getLogger(__name__)


def _parse_json_lines(stdout: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return items


def _ensure_query_param(url: str, param: str = "id", value: str = "1") -> str:
    """sqlmap needs at least one injectable parameter; append a benign one if missing."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if qs:
        return url
    new_query = urlencode({param: value})
    return urlunparse(parsed._replace(query=new_query))


def _curl_for(url: str, method: str = "GET", auth_header: str | None = None) -> str:
    parts = [f"curl -sk -X {method}"]
    if auth_header:
        parts.append(f"-H 'Authorization: {auth_header}'")
    parts.append(f"'{url}'")
    return " ".join(parts)


async def run_sqlmap(
    target: str,
    timeout: int,
    *,
    auth_header: str | None = None,
    delay_ms: int = 0,
    level: int = 2,
    risk: int = 2,
) -> ToolRunResult:
    url = _ensure_query_param(base_url(target))
    runner = ToolRunner(settings.sqlmap_path, "sqlmap")
    args = [
        "-u",
        url,
        "--batch",
        "--random-agent",
        f"--level={max(1, min(level, 5))}",
        f"--risk={max(1, min(risk, 3))}",
        "--forms",
        "--crawl=0",
        "--output-dir=/tmp/p4nt3xia-sqlmap",
        "--flush-session",
    ]
    if delay_ms > 0:
        args.extend(["--delay", str(max(0, delay_ms / 1000))])
    if auth_header:
        # sqlmap --header expects "Name: value"
        header = (
            auth_header
            if ":" in auth_header
            else f"Authorization: {auth_header}"
        )
        args.extend(["--header", header])

    result = await runner.run(args, timeout=timeout)
    # sqlmap often exits non-zero when vulnerabilities found
    if result.status == "failed" and result.stdout:
        result.status = "completed"

    findings: list[dict[str, Any]] = []
    text = (result.stdout or "") + "\n" + (result.stderr or "")
    injectable = re.findall(
        r"Parameter:\s*([^\s]+)\s*\((GET|POST|Cookie|Header)\)",
        text,
        re.IGNORECASE,
    )
    dbms_hits = re.findall(r"back-end DBMS:\s*(.+)", text, re.IGNORECASE)
    if "is vulnerable" in text.lower() or injectable:
        for param, loc in injectable or [("unknown", "GET")]:
            findings.append(
                {
                    "title": f"SQL Injection — parameter '{param}' ({loc})",
                    "severity": "critical",
                    "finding_type": "sqli",
                    "description": (
                        f"sqlmap reported injectable parameter '{param}' via {loc}."
                        + (f" DBMS: {dbms_hits[0].strip()}" if dbms_hits else "")
                    ),
                    "poc_request": f"{loc} {url}\nParameter: {param}",
                    "poc_response": "See sqlmap output for payload confirmation",
                    "poc_curl": _curl_for(url, auth_header=auth_header),
                    "remediation": (
                        "Use parameterized queries / prepared statements. "
                        "Validate and encode all user input. Prefer ORM bind parameters."
                    ),
                    "references": [
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                    ],
                    "cvss_score": 9.8,
                }
            )
    elif "all tested parameters do not appear to be injectable" in text.lower():
        findings.append(
            {
                "title": "sqlmap: no injectable parameters detected",
                "severity": "info",
                "finding_type": "sqli",
                "description": "sqlmap completed without confirming SQL injection.",
                "poc_curl": _curl_for(url, auth_header=auth_header),
                "remediation": None,
                "references": [],
                "cvss_score": 0.0,
            }
        )

    result.parsed_output = {
        "findings": findings,
        "url": url,
        "dbms": dbms_hits[0].strip() if dbms_hits else None,
    }
    return result


async def run_dalfox(
    target: str,
    timeout: int,
    *,
    auth_header: str | None = None,
    delay_ms: int = 0,
) -> ToolRunResult:
    url = base_url(target)
    runner = ToolRunner(settings.dalfox_path, "dalfox")
    args = [
        "url",
        url,
        "--format",
        "json",
        "--silence",
        "--skip-bav",
    ]
    if delay_ms > 0:
        args.extend(["--delay", str(delay_ms)])
    if auth_header:
        header = (
            auth_header
            if ":" in auth_header
            else f"Authorization: {auth_header}"
        )
        args.extend(["--header", header])

    result = await runner.run(args, timeout=timeout)
    if result.status == "failed" and result.stdout:
        result.status = "completed"

    findings: list[dict[str, Any]] = []
    for item in _parse_json_lines(result.stdout):
        # Dalfox JSON shapes vary by version
        data_type = (item.get("type") or item.get("type_str") or "reflected").lower()
        param = item.get("param") or item.get("param_name") or "unknown"
        payload = item.get("payload") or item.get("evidence") or ""
        severity = "high"
        if "stored" in data_type:
            severity = "critical"
        elif "dom" in data_type:
            severity = "high"
        findings.append(
            {
                "title": f"XSS ({data_type}) — param '{param}'",
                "severity": severity,
                "finding_type": "xss",
                "description": item.get("message")
                or item.get("cwe")
                or f"Dalfox reported XSS via parameter '{param}'.",
                "poc_request": f"GET {url}\nParam: {param}\nPayload: {payload}",
                "poc_response": str(item.get("evidence") or item.get("data") or "")[:4000],
                "poc_curl": _curl_for(
                    f"{url}{'&' if '?' in url else '?'}{param}={payload}"
                    if param != "unknown"
                    else url,
                    auth_header=auth_header,
                ),
                "remediation": (
                    "Context-aware output encoding. Use a Trusted Types CSP. "
                    "Avoid reflecting unsanitized user input into HTML/JS."
                ),
                "references": [
                    "https://owasp.org/www-community/attacks/xss/",
                ],
                "cvss_score": 9.0 if severity == "critical" else 7.5,
                "raw": item,
            }
        )

    # Fallback: grep human-readable PoC lines
    if not findings and result.stdout:
        for line in result.stdout.splitlines():
            if "[V]" in line or "POC" in line.upper() or "reflected" in line.lower():
                findings.append(
                    {
                        "title": "XSS finding (Dalfox)",
                        "severity": "high",
                        "finding_type": "xss",
                        "description": line.strip()[:500],
                        "poc_request": line.strip()[:1000],
                        "poc_curl": _curl_for(url, auth_header=auth_header),
                        "remediation": "Encode user-controlled output; enforce CSP.",
                        "references": [
                            "https://owasp.org/www-community/attacks/xss/",
                        ],
                        "cvss_score": 7.5,
                    }
                )
                break

    result.parsed_output = {"findings": findings, "url": url}
    return result


async def run_nuclei_exploit(
    target: str,
    timeout: int,
    *,
    auth_header: str | None = None,
) -> ToolRunResult:
    """Nuclei with high/critical (+ exploit-tagged) templates — Attack Mode only."""
    url = base_url(target)
    runner = ToolRunner(settings.nuclei_path, "nuclei_exploit")
    args = [
        "-u",
        url,
        "-severity",
        "high,critical",
        "-tags",
        "exploit,cve,rce,sqli,xss",
        "-jsonl",
        "-silent",
        "-nc",
    ]
    if auth_header:
        header = (
            auth_header
            if ":" in auth_header
            else f"Authorization: {auth_header}"
        )
        args.extend(["-H", header])

    result = await runner.run(args, timeout=timeout)
    if result.status == "failed" and result.stdout:
        result.status = "completed"

    severity_cvss = {
        "info": 0.0,
        "low": 3.1,
        "medium": 5.5,
        "high": 7.5,
        "critical": 9.8,
    }
    findings: list[dict[str, Any]] = []
    for item in _parse_json_lines(result.stdout):
        info = item.get("info") or {}
        sev = (info.get("severity") or "high").lower()
        if sev not in severity_cvss:
            sev = "high"
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]
        matched = item.get("matched-at") or item.get("host") or url
        req = item.get("request") or ""
        resp = item.get("response") or ""
        curl = item.get("curl-command") or _curl_for(matched, auth_header=auth_header)
        findings.append(
            {
                "title": info.get("name") or item.get("template-id") or "Nuclei exploit finding",
                "severity": sev,
                "finding_type": "exploit",
                "description": info.get("description") or f"Matched at {matched}",
                "poc_request": req[:8000] if isinstance(req, str) else str(req)[:8000],
                "poc_response": resp[:8000] if isinstance(resp, str) else str(resp)[:8000],
                "poc_curl": curl if isinstance(curl, str) else _curl_for(matched),
                "remediation": (
                    (info.get("remediation") if isinstance(info.get("remediation"), str) else None)
                    or "Apply vendor patches; restrict exposure; verify authz on the affected path."
                ),
                "references": list(refs)[:20],
                "cve_id": (info.get("classification") or {}).get("cve-id")
                if isinstance(info.get("classification"), dict)
                else None,
                "cvss_score": severity_cvss.get(sev, 7.5),
                "raw": item,
            }
        )

    result.parsed_output = {"findings": findings, "url": url}
    return result
