"""Attack Mode tool wrappers — sqlmap, Dalfox, Nuclei, hydra, SSRFmap, JWT_Tool."""

from __future__ import annotations

import json
import logging
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from app.config import settings
from app.services.target_utils import base_url, extract_host
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


def _resolve_wordlist(path: str) -> str:
    p = Path(path)
    if p.exists():
        return str(p)
    alt = Path(__file__).resolve().parents[2] / "tools" / "wordlists" / "passwords.txt"
    return str(alt) if alt.exists() else path


async def run_hydra(
    target: str,
    timeout: int,
    *,
    auth_header: str | None = None,  # unused — kept for signature parity
    delay_ms: int = 0,
    username: str = "admin",
) -> ToolRunResult:
    """HTTP form brute-force via hydra (small wordlist, capped)."""
    _ = auth_header
    host = extract_host(target)
    url = base_url(target)
    wordlist = _resolve_wordlist(settings.hydra_wordlist)
    runner = ToolRunner(settings.hydra_path, "hydra")

    if not Path(wordlist).exists():
        return ToolRunResult(
            tool_name="hydra",
            command=[settings.hydra_path],
            stderr=f"Password wordlist not found: {wordlist}",
            status="skipped",
            skip_reason=f"Password wordlist not found: {wordlist}",
        )

    delay_s = max(0, delay_ms / 1000)
    args = [
        "-l",
        username,
        "-P",
        wordlist,
        "-t",
        "4",
        "-f",
        "-V",
    ]
    if delay_s > 0:
        args.extend(["-W", str(int(delay_s) or 1)])

    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    path = parsed.path if parsed.path and parsed.path != "/" else "/login"
    form_spec = f"{path}:username=^USER^&password=^PASS^:F=invalid"
    module = "https-post-form" if scheme == "https" else "http-post-form"
    args.extend([host, module, form_spec])

    result = await runner.run(args, timeout=timeout)
    if result.status == "failed" and result.stdout:
        result.status = "completed"

    findings: list[dict[str, Any]] = []
    text = (result.stdout or "") + "\n" + (result.stderr or "")
    cred_hits = re.findall(
        r"login:\s*(\S+)\s+password:\s*(\S+)",
        text,
        re.IGNORECASE,
    )
    for user, password in cred_hits:
        findings.append(
            {
                "title": f"Weak credentials — {user}:{password}",
                "severity": "critical",
                "finding_type": "brute_force",
                "description": f"Hydra recovered valid credentials for {user} on {host}.",
                "poc_request": f"POST {url}{path}\nusername={user}&password={password}",
                "poc_response": "Authentication succeeded (hydra)",
                "poc_curl": (
                    f"curl -sk -X POST '{url.rstrip('/')}{path}' "
                    f"-d 'username={user}&password={password}'"
                ),
                "remediation": (
                    "Enforce strong passwords, account lockout, MFA, and rate limiting. "
                    "Disable default credentials."
                ),
                "references": [
                    "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
                ],
                "cvss_score": 9.8,
            }
        )

    if not findings and result.status == "completed":
        findings.append(
            {
                "title": "Hydra: no credentials recovered",
                "severity": "info",
                "finding_type": "brute_force",
                "description": f"Brute-force against {host} with user '{username}' found no hits.",
                "remediation": None,
                "references": [],
                "cvss_score": 0.0,
            }
        )

    result.parsed_output = {
        "findings": findings,
        "host": host,
        "username": username,
    }
    return result


async def run_ssrfmap(
    target: str,
    timeout: int,
    *,
    auth_header: str | None = None,
) -> ToolRunResult:
    """SSRFmap against a generated request with common SSRF parameter names."""
    url = base_url(target)
    runner = ToolRunner(settings.ssrfmap_path, "ssrfmap")
    if not runner.is_available():
        return await runner.run([], timeout=1)

    parsed = urlparse(url)
    host_header = parsed.netloc or extract_host(target)
    path = parsed.path or "/"
    if "?" in path:
        req_path = f"{path}&url=http://127.0.0.1:80/"
    else:
        req_path = f"{path}?url=http://127.0.0.1:80/" if path.startswith("/") else "/?url=http://127.0.0.1:80/"
    ssrf_url = f"{url}{'&' if '?' in url else '?'}url=http://127.0.0.1:80/"
    req_lines = [
        f"GET {req_path} HTTP/1.1",
        f"Host: {host_header}",
        "User-Agent: P4NT3XIA-SSRFmap",
        "Accept: */*",
        "Connection: close",
    ]
    if auth_header:
        header = (
            auth_header
            if ":" in auth_header
            else f"Authorization: {auth_header}"
        )
        req_lines.insert(2, header)
    req_body = "\n".join(req_lines) + "\n\n"

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write(req_body)
        req_path_file = fh.name

    try:
        args = ["-r", req_path_file, "-p", "url", "-m", "readfiles"]
        result = await runner.run(args, timeout=timeout)
    finally:
        try:
            Path(req_path_file).unlink(missing_ok=True)
        except OSError:
            pass

    if result.status == "failed" and (result.stdout or result.stderr):
        result.status = "completed"

    text = (result.stdout or "") + "\n" + (result.stderr or "")
    findings: list[dict[str, Any]] = []
    vulnerable = any(
        marker in text.lower()
        for marker in ("vulnerable", "ssrf", "root:", "file://", "[+]")
    )
    if vulnerable and "root:" in text:
        findings.append(
            {
                "title": "SSRF — local file / internal access indicated",
                "severity": "critical",
                "finding_type": "ssrf",
                "description": "SSRFmap reported indicators of server-side request forgery / local read.",
                "poc_request": req_body[:2000],
                "poc_response": text[:3000],
                "poc_curl": _curl_for(ssrf_url, auth_header=auth_header),
                "remediation": (
                    "Block private IP ranges and metadata endpoints; validate URL schemes; "
                    "use allowlists for outbound requests."
                ),
                "references": [
                    "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                ],
                "cvss_score": 9.1,
            }
        )
    elif vulnerable:
        findings.append(
            {
                "title": "Possible SSRF (SSRFmap signal)",
                "severity": "high",
                "finding_type": "ssrf",
                "description": "SSRFmap produced positive signals; verify with a collaborator / internal probe.",
                "poc_request": req_body[:2000],
                "poc_response": text[:3000],
                "poc_curl": _curl_for(ssrf_url, auth_header=auth_header),
                "remediation": "Restrict outbound fetches; deny link-local and cloud metadata IPs.",
                "references": [
                    "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                ],
                "cvss_score": 7.5,
            }
        )
    else:
        findings.append(
            {
                "title": "SSRFmap: no confirmed SSRF",
                "severity": "info",
                "finding_type": "ssrf",
                "description": "SSRFmap completed without confirming SSRF on parameter 'url'.",
                "poc_curl": _curl_for(ssrf_url, auth_header=auth_header),
                "remediation": None,
                "references": [],
                "cvss_score": 0.0,
            }
        )

    result.parsed_output = {"findings": findings, "url": url}
    return result


def _extract_jwt(auth_header: str | None) -> str | None:
    if not auth_header:
        return None
    value = auth_header.strip()
    if value.lower().startswith("bearer "):
        value = value[7:].strip()
    elif ":" in value:
        _, _, rest = value.partition(":")
        rest = rest.strip()
        if rest.lower().startswith("bearer "):
            rest = rest[7:].strip()
        value = rest
    if value.count(".") == 2 and len(value) > 20:
        return value
    return None


async def run_jwt_tool(
    target: str,
    timeout: int,
    *,
    auth_header: str | None = None,
) -> ToolRunResult:
    """JWT_Tool — examine / attack JWT from Authorization header."""
    url = base_url(target)
    token = _extract_jwt(auth_header)
    runner = ToolRunner(settings.jwt_tool_path, "jwt_tool")

    if not token:
        return ToolRunResult(
            tool_name="jwt_tool",
            command=[settings.jwt_tool_path],
            stderr="No JWT found in auth_header (expected Bearer eyJ…)",
            status="skipped",
            skip_reason="Provide a Bearer JWT in the Auth header to run JWT_Tool",
            parsed_output={
                "findings": [
                    {
                        "title": "JWT_Tool skipped — no token",
                        "severity": "info",
                        "finding_type": "jwt",
                        "description": (
                            "Pass an Authorization Bearer JWT to enable alg confusion / claim tests."
                        ),
                        "remediation": None,
                        "references": [],
                        "cvss_score": 0.0,
                    }
                ]
            },
        )

    header = (
        auth_header
        if auth_header and ":" in auth_header
        else f"Authorization: Bearer {token}"
    )
    args = [
        token,
        "-t",
        url,
        "-rh",
        header,
        "-M",
        "at",
    ]
    result = await runner.run(args, timeout=timeout)
    if result.status == "failed" and result.stdout:
        result.status = "completed"

    text = (result.stdout or "") + "\n" + (result.stderr or "")
    findings: list[dict[str, Any]] = []

    if re.search(
        r"none.?alg|alg.?none|Algorithm.?confusion|\"alg\"\s*:\s*\"none\"",
        text,
        re.I,
    ):
        findings.append(
            {
                "title": "JWT algorithm none / confusion possible",
                "severity": "critical",
                "finding_type": "jwt",
                "description": "JWT_Tool indicated algorithm none or algorithm confusion susceptibility.",
                "poc_request": f"Authorization: Bearer {token[:40]}…",
                "poc_response": text[:3000],
                "poc_curl": _curl_for(url, auth_header=f"Bearer {token}"),
                "remediation": (
                    "Explicitly whitelist RS256/ES256 (or HS256 with strong secrets). "
                    "Reject alg=none; enforce key type checks."
                ),
                "references": ["https://portswigger.net/web-security/jwt"],
                "cvss_score": 9.8,
            }
        )

    if re.search(r"signature.*(ok|valid|bypass)|tampered.*accepted", text, re.I):
        findings.append(
            {
                "title": "JWT signature issues detected",
                "severity": "high",
                "finding_type": "jwt",
                "description": "JWT_Tool reported signature validation weaknesses.",
                "poc_request": header,
                "poc_response": text[:3000],
                "poc_curl": _curl_for(url, auth_header=f"Bearer {token}"),
                "remediation": "Verify signatures with the correct key material on every request.",
                "references": ["https://portswigger.net/web-security/jwt"],
                "cvss_score": 8.1,
            }
        )

    if not findings and result.status in ("completed", "failed"):
        findings.append(
            {
                "title": "JWT_Tool analysis completed",
                "severity": "info",
                "finding_type": "jwt",
                "description": (
                    "No high-confidence JWT attack confirmed. Review JWT_Tool stdout for claim details."
                ),
                "poc_response": text[:4000],
                "poc_curl": _curl_for(url, auth_header=f"Bearer {token}"),
                "remediation": "Use short-lived tokens, rotate secrets, validate iss/aud/exp strictly.",
                "references": ["https://portswigger.net/web-security/jwt"],
                "cvss_score": 0.0,
            }
        )

    result.parsed_output = {"findings": findings, "url": url}
    return result
