"""Individual Deep Scan tool wrappers."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from app.config import settings
from app.services.target_utils import base_url, extract_domain, extract_host
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


async def run_subfinder(target: str, timeout: int) -> ToolRunResult:
    domain = extract_domain(target)
    runner = ToolRunner(settings.subfinder_path, "subfinder")
    result = await runner.run(["-d", domain, "-silent", "-oJ"], timeout=timeout)
    subdomains: list[str] = []
    for item in _parse_json_lines(result.stdout):
        host = item.get("host") or item.get("input")
        if host:
            subdomains.append(host)
    if not subdomains and result.stdout.strip():
        # Fallback: plain line output
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("{"):
                subdomains.append(line)
    result.parsed_output = {"subdomains": sorted(set(subdomains)), "domain": domain}
    return result


async def run_nmap(target: str, timeout: int) -> ToolRunResult:
    host = extract_host(target)
    runner = ToolRunner(settings.nmap_path, "nmap")
    # Safe SYN-style port discovery — use -sT if -sS needs root; prefer --top-ports
    result = await runner.run(
        ["-sT", "-sV", "-T3", "--top-ports", "100", "-oX", "-", host],
        timeout=timeout,
    )
    ports: list[dict[str, Any]] = []
    # Lightweight XML parse without lxml dependency
    for match in re.finditer(
        r'<port protocol="(?P<proto>\w+)" portid="(?P<xml>\d+)".*?'
        r'<state state="(?P<state>\w+)".*?'
        r'(?:<service name="(?P<service>[^"]*)"[^/]*?(?:product="(?P<product>[^"]*)")?[^/]*?(?:version="(?P<version>[^"]*)")?[^/]*?/>)?',
        result.stdout,
        re.DOTALL,
    ):
        if match.group("state") != "open":
            continue
        ports.append(
            {
                "port": int(match.group("port")),
                "protocol": match.group("proto"),
                "state": match.group("state"),
                "service": match.group("service") or "",
                "product": match.group("product") or "",
                "version": match.group("version") or "",
            }
        )
    # Fallback: grepable open ports from human-readable lines
    if not ports:
        for line in result.stdout.splitlines():
            m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", line.strip())
            if m:
                ports.append(
                    {
                        "port": int(m.group(1)),
                        "protocol": m.group(2),
                        "state": "open",
                        "service": m.group(3),
                        "product": (m.group(4) or "").strip(),
                        "version": "",
                    }
                )
    result.parsed_output = {"ports": ports, "host": host}
    return result


async def run_ffuf(target: str, timeout: int, threads: int = 3) -> ToolRunResult:
    url = f"{base_url(target)}/FUZZ"
    wordlist = settings.ffuf_wordlist
    if not Path(wordlist).exists():
        # Fallback bundled path relative to backend
        alt = Path(__file__).resolve().parents[2] / "tools" / "wordlists" / "common.txt"
        wordlist = str(alt) if alt.exists() else wordlist

    runner = ToolRunner(settings.ffuf_path, "ffuf")
    if not Path(wordlist).exists():
        return ToolRunResult(
            tool_name="ffuf",
            command=[settings.ffuf_path, "-w", wordlist],
            stderr=f"Wordlist not found: {wordlist}",
            status="skipped",
            skip_reason=f"Wordlist not found: {wordlist}",
        )

    if not runner.is_available():
        return await runner.run([], timeout=1)

    result = await runner.run(
        [
            "-u",
            url,
            "-w",
            wordlist,
            "-mc",
            "200,201,204,301,302,307,401,403",
            "-t",
            str(threads),
            "-of",
            "json",
            "-o",
            "/dev/stdout",
            "-s",
        ],
        timeout=timeout,
    )
    endpoints: list[dict[str, Any]] = []
    try:
        # ffuf may wrap JSON or print raw; try full parse then line filter
        data = json.loads(result.stdout) if result.stdout.strip().startswith("{") else None
        if data and "results" in data:
            for item in data["results"]:
                endpoints.append(
                    {
                        "url": item.get("url") or item.get("input", {}).get("FUZZ"),
                        "status": item.get("status"),
                        "length": item.get("length"),
                        "words": item.get("words"),
                    }
                )
    except json.JSONDecodeError:
        for item in _parse_json_lines(result.stdout):
            if "url" in item or "status" in item:
                endpoints.append(
                    {
                        "url": item.get("url"),
                        "status": item.get("status"),
                        "length": item.get("length"),
                    }
                )
    result.parsed_output = {"endpoints": endpoints, "fuzz_url": url}
    return result


async def run_whatweb(target: str, timeout: int) -> ToolRunResult:
    url = base_url(target)
    runner = ToolRunner(settings.whatweb_path, "whatweb")
    result = await runner.run(["--log-json=-", "-a", "1", url], timeout=timeout)
    technologies: list[str] = []
    plugins: list[dict[str, Any]] = []
    for item in _parse_json_lines(result.stdout):
        plugins_data = item.get("plugins") or {}
        for name, meta in plugins_data.items():
            technologies.append(name)
            plugins.append({"name": name, "meta": meta})
    if not technologies and result.stdout.strip():
        # Human-readable: Target [status] Tech1[...] Tech2[...]
        for line in result.stdout.splitlines():
            parts = re.findall(r"([A-Za-z0-9_\-]+)(?:\[([^\]]*)\])?", line)
            for name, _ in parts:
                if name.lower() not in ("http", "https", "www") and len(name) > 2:
                    technologies.append(name)
    result.parsed_output = {
        "technologies": sorted(set(technologies)),
        "plugins": plugins,
        "url": url,
    }
    return result


async def run_nuclei(target: str, timeout: int) -> ToolRunResult:
    """Safe Nuclei scan: severity info,low,medium only — exclude exploit tags."""
    url = base_url(target)
    runner = ToolRunner(settings.nuclei_path, "nuclei")
    result = await runner.run(
        [
            "-u",
            url,
            "-severity",
            "info,low,medium",
            "-etags",
            "exploit,intrusive,dos",
            "-jsonl",
            "-silent",
            "-nc",
        ],
        timeout=timeout,
    )
    findings: list[dict[str, Any]] = []
    for item in _parse_json_lines(result.stdout):
        info = item.get("info") or {}
        findings.append(
            {
                "name": info.get("name") or item.get("template-id") or "Nuclei finding",
                "severity": (info.get("severity") or "info").lower(),
                "template_id": item.get("template-id") or item.get("templateID"),
                "matched_at": item.get("matched-at") or item.get("host") or url,
                "description": info.get("description") or "",
                "reference": info.get("reference") or [],
                "tags": info.get("tags") or [],
                "raw": item,
            }
        )
    result.parsed_output = {"findings": findings, "url": url}
    return result


async def run_katana(target: str, timeout: int) -> ToolRunResult:
    url = base_url(target)
    runner = ToolRunner(settings.katana_path, "katana")
    result = await runner.run(
        [
            "-u",
            url,
            "-silent",
            "-jsonl",
            "-d",
            "2",
            "-c",
            "5",
            "-ef",
            "css,png,jpg,jpeg,gif,svg,woff,woff2,ico",
        ],
        timeout=timeout,
    )
    urls: list[str] = []
    for item in _parse_json_lines(result.stdout):
        u = item.get("request", {}).get("endpoint") or item.get("url") or item.get("endpoint")
        if u:
            urls.append(u)
    if not urls:
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("http"):
                urls.append(line)
    result.parsed_output = {"urls": sorted(set(urls)), "seed": url}
    return result
