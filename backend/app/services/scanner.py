"""Scan orchestrator — runs Deep Scan pipeline and persists results."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.target import Target
from app.models.tool_result import ToolResult
from app.schemas.scan import AttackScanRequest, DeepScanRequest
from app.services import attack as attack_tools
from app.services import custom_payloads
from app.services import deep_scan as tools
from app.services.target_utils import is_valid_target
from app.services.tool_runner import ToolRunResult
from app.services.ws_manager import ws_manager


logger = logging.getLogger(__name__)

SEVERITY_CVSS = {
    "info": 0.0,
    "low": 3.1,
    "medium": 5.5,
    "high": 7.5,
    "critical": 9.8,
}

# Pipeline order per Phase 1 MVP
DEEP_SCAN_PIPELINE = [
    ("subfinder", "subdomain_enum", tools.run_subfinder),
    ("nmap", "port_scan", tools.run_nmap),
    ("ffuf", "directory_fuzz", tools.run_ffuf),
    ("whatweb", "tech_detect", tools.run_whatweb),
    ("nuclei", "safe_vuln_scan", tools.run_nuclei),
    ("katana", "crawl", tools.run_katana),
]

# Phase 2 + Phase 3 Attack Mode pipeline: (tool_name, options_key)
ATTACK_PIPELINE = [
    ("sqlmap", "sql_injection"),
    ("dalfox", "xss"),
    ("nuclei_exploit", "nuclei_exploit"),
    ("hydra", "brute_force"),
    ("ssrfmap", "ssrf"),
    ("jwt_tool", "jwt_attack"),
    ("cmdi", "command_injection"),
    ("lfi", "lfi"),
    ("file_upload", "file_upload"),
    ("idor", "idor"),
]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScannerService:
    def __init__(self) -> None:
        self._tasks: dict[str, asyncio.Task] = {}

    def create_deep_scan(self, db: Session, payload: DeepScanRequest) -> Scan:
        if not is_valid_target(payload.target):
            raise ValueError("Invalid target format. Provide a URL, domain, or IP.")

        target = (
            db.query(Target)
            .filter(Target.value == payload.target.strip())
            .first()
        )
        if not target:
            target = Target(
                value=payload.target.strip(),
                type=payload.target_type,
            )
            db.add(target)
            db.flush()

        scan = Scan(
            target_id=target.id,
            mode="deep_scan",
            status="pending",
            progress=0.0,
            configuration={
                "target": payload.target.strip(),
                "options": payload.options.model_dump(),
            },
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan

    def create_attack_scan(self, db: Session, payload: AttackScanRequest) -> Scan:
        if not is_valid_target(payload.target):
            raise ValueError("Invalid target format. Provide a URL, domain, or IP.")
        if not payload.options.authorized:
            raise ValueError(
                "Authorization confirmation required. Set options.authorized=true "
                "only for systems you are permitted to attack."
            )

        target = (
            db.query(Target)
            .filter(Target.value == payload.target.strip())
            .first()
        )
        if not target:
            target = Target(
                value=payload.target.strip(),
                type=payload.target_type,
            )
            db.add(target)
            db.flush()

        opts = payload.options.model_dump()
        scan = Scan(
            target_id=target.id,
            mode="attack",
            status="pending",
            progress=0.0,
            configuration={
                "target": payload.target.strip(),
                "auth_header": payload.auth_header,
                "options": opts,
            },
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan

    def start_scan(self, scan_id: str, *, mode: str | None = None) -> None:
        if scan_id in self._tasks and not self._tasks[scan_id].done():
            return
        if mode is None:
            db = SessionLocal()
            try:
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                mode = scan.mode if scan else "deep_scan"
            finally:
                db.close()
        if mode == "attack":
            task = asyncio.create_task(self._run_attack(scan_id))
        else:
            task = asyncio.create_task(self._run_deep_scan(scan_id))
        self._tasks[scan_id] = task

    async def cancel_scan(self, scan_id: str) -> bool:
        task = self._tasks.get(scan_id)
        if task and not task.done():
            task.cancel()
            db = SessionLocal()
            try:
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                if scan and scan.status == "running":
                    scan.status = "cancelled"
                    scan.completed_at = _utcnow()
                    db.commit()
                    await self._emit(
                        scan_id,
                        status="cancelled",
                        progress=scan.progress,
                        message="Scan cancelled by user",
                    )
            finally:
                db.close()
            return True
        return False

    async def _emit(
        self,
        scan_id: str,
        *,
        status: str,
        progress: float,
        message: str = "",
        current_tool: str | None = None,
        finding: dict | None = None,
        tool_result: dict | None = None,
    ) -> None:
        await ws_manager.broadcast(
            scan_id,
            {
                "scan_id": scan_id,
                "status": status,
                "progress": progress,
                "current_tool": current_tool,
                "message": message,
                "finding": finding,
                "tool_result": tool_result,
            },
        )

    async def _run_deep_scan(self, scan_id: str) -> None:
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return

            options = (scan.configuration or {}).get("options") or {}
            target_value = (scan.configuration or {}).get("target") or ""
            if not target_value and scan.target:
                target_value = scan.target.value

            scan.status = "running"
            scan.started_at = _utcnow()
            scan.progress = 0.0
            db.commit()

            # Brief pause so WebSocket clients can attach before first events
            await asyncio.sleep(0.3)

            await self._emit(
                scan_id,
                status="running",
                progress=0,
                message=f"Starting Deep Scan on {target_value}",
            )

            enabled_steps = [
                (name, key, fn)
                for name, key, fn in DEEP_SCAN_PIPELINE
                if options.get(key, True)
            ]
            if not enabled_steps:
                scan.status = "failed"
                scan.error_message = "No scan tools enabled"
                scan.completed_at = _utcnow()
                db.commit()
                await self._emit(
                    scan_id,
                    status="failed",
                    progress=0,
                    message="No scan tools enabled",
                )
                return

            timeout = int(options.get("timeout", 30)) * 10  # allow longer per-tool budget
            timeout = max(60, min(timeout, 600))
            threads = int(options.get("threads", 3))
            step_count = len(enabled_steps)

            for index, (tool_name, _opt_key, runner_fn) in enumerate(enabled_steps):
                progress_start = (index / step_count) * 100
                progress_end = ((index + 1) / step_count) * 100

                scan.current_tool = tool_name
                scan.progress = progress_start
                db.commit()

                await self._emit(
                    scan_id,
                    status="running",
                    progress=progress_start,
                    current_tool=tool_name,
                    message=f"Running {tool_name}...",
                )

                try:
                    if tool_name == "ffuf":
                        result: ToolRunResult = await runner_fn(
                            target_value, timeout, threads=threads
                        )
                    else:
                        result = await runner_fn(target_value, timeout)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.exception("Tool %s crashed", tool_name)
                    result = ToolRunResult(
                        tool_name=tool_name,
                        command=[tool_name],
                        stderr=str(exc),
                        status="failed",
                    )

                tr = ToolResult(
                    scan_id=scan_id,
                    tool_name=result.tool_name,
                    command=result.command_str,
                    stdout=result.stdout[:500_000] if result.stdout else None,
                    stderr=result.stderr[:100_000] if result.stderr else None,
                    exit_code=result.exit_code,
                    duration_ms=result.duration_ms,
                    status=result.status,
                    parsed_output=result.parsed_output or {},
                )
                db.add(tr)
                db.flush()

                findings = self._findings_from_tool(scan_id, result)
                for f in findings:
                    db.add(f)
                db.commit()

                for f in findings:
                    db.refresh(f)
                    await self._emit(
                        scan_id,
                        status="running",
                        progress=progress_end,
                        current_tool=tool_name,
                        message=f"Finding: {f.title}",
                        finding={
                            "id": f.id,
                            "title": f.title,
                            "severity": f.severity,
                            "finding_type": f.finding_type,
                            "description": f.description,
                        },
                    )

                status_msg = result.status
                if result.status == "skipped":
                    status_msg = f"skipped ({result.skip_reason or 'not available'})"
                await self._emit(
                    scan_id,
                    status="running",
                    progress=progress_end,
                    current_tool=tool_name,
                    message=f"Finished {tool_name}: {status_msg}",
                    tool_result={
                        "tool_name": tool_name,
                        "status": result.status,
                        "duration_ms": result.duration_ms,
                        "parsed_summary": self._summarize_parsed(result),
                    },
                )

                scan.progress = progress_end
                db.commit()

            scan.status = "completed"
            scan.progress = 100.0
            scan.current_tool = None
            scan.completed_at = _utcnow()
            db.commit()
            await self._emit(
                scan_id,
                status="completed",
                progress=100,
                message="Deep Scan completed",
            )
        except asyncio.CancelledError:
            logger.info("Scan %s cancelled", scan_id)
            raise
        except Exception as exc:
            logger.exception("Scan %s failed", scan_id)
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "failed"
                scan.error_message = str(exc)[:1000]
                scan.completed_at = _utcnow()
                db.commit()
            await self._emit(
                scan_id,
                status="failed",
                progress=0,
                message=f"Scan failed: {exc}",
            )
        finally:
            db.close()
            self._tasks.pop(scan_id, None)

    async def _run_attack(self, scan_id: str) -> None:
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return

            options = (scan.configuration or {}).get("options") or {}
            auth_header = (scan.configuration or {}).get("auth_header")
            target_value = (scan.configuration or {}).get("target") or ""
            if not target_value and scan.target:
                target_value = scan.target.value

            scan.status = "running"
            scan.started_at = _utcnow()
            scan.progress = 0.0
            db.commit()

            await asyncio.sleep(0.3)
            await self._emit(
                scan_id,
                status="running",
                progress=0,
                message=f"Launching Attack Mode on {target_value} (authorized)",
            )

            phase2_defaults = {"sql_injection", "xss", "nuclei_exploit"}
            enabled: list[tuple[str, str]] = [
                (name, key)
                for name, key in ATTACK_PIPELINE
                if options.get(key, key in phase2_defaults)
            ]
            if not enabled:
                scan.status = "failed"
                scan.error_message = "No attack vectors enabled"
                scan.completed_at = _utcnow()
                db.commit()
                await self._emit(
                    scan_id,
                    status="failed",
                    progress=0,
                    message="No attack vectors enabled",
                )
                return

            timeout = int(options.get("timeout", 60)) * 5
            timeout = max(120, min(timeout, 900))
            delay_ms = int(options.get("delay_ms", 0))
            level = int(options.get("sqlmap_level", 2))
            risk = int(options.get("sqlmap_risk", 2))
            hydra_user = str(options.get("hydra_username") or "admin")
            step_count = len(enabled)

            runners = {
                "sqlmap": lambda: attack_tools.run_sqlmap(
                    target_value,
                    timeout,
                    auth_header=auth_header,
                    delay_ms=delay_ms,
                    level=level,
                    risk=risk,
                ),
                "dalfox": lambda: attack_tools.run_dalfox(
                    target_value,
                    timeout,
                    auth_header=auth_header,
                    delay_ms=delay_ms,
                ),
                "nuclei_exploit": lambda: attack_tools.run_nuclei_exploit(
                    target_value,
                    timeout,
                    auth_header=auth_header,
                ),
                "hydra": lambda: attack_tools.run_hydra(
                    target_value,
                    timeout,
                    auth_header=auth_header,
                    delay_ms=delay_ms,
                    username=hydra_user,
                ),
                "ssrfmap": lambda: attack_tools.run_ssrfmap(
                    target_value,
                    timeout,
                    auth_header=auth_header,
                ),
                "jwt_tool": lambda: attack_tools.run_jwt_tool(
                    target_value,
                    timeout,
                    auth_header=auth_header,
                ),
                "cmdi": lambda: custom_payloads.run_cmdi(
                    target_value,
                    timeout,
                    auth_header=auth_header,
                    delay_ms=delay_ms,
                ),
                "lfi": lambda: custom_payloads.run_lfi(
                    target_value,
                    timeout,
                    auth_header=auth_header,
                    delay_ms=delay_ms,
                ),
                "file_upload": lambda: custom_payloads.run_file_upload(
                    target_value,
                    timeout,
                    auth_header=auth_header,
                    delay_ms=delay_ms,
                ),
                "idor": lambda: custom_payloads.run_idor(
                    target_value,
                    timeout,
                    auth_header=auth_header,
                    delay_ms=delay_ms,
                ),
            }

            for index, (tool_name, _opt_key) in enumerate(enabled):
                progress_start = (index / step_count) * 100
                progress_end = ((index + 1) / step_count) * 100

                scan.current_tool = tool_name
                scan.progress = progress_start
                db.commit()

                await self._emit(
                    scan_id,
                    status="running",
                    progress=progress_start,
                    current_tool=tool_name,
                    message=f"Running {tool_name}...",
                )

                try:
                    result: ToolRunResult = await runners[tool_name]()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.exception("Attack tool %s crashed", tool_name)
                    result = ToolRunResult(
                        tool_name=tool_name,
                        command=[tool_name],
                        stderr=str(exc),
                        status="failed",
                    )

                tr = ToolResult(
                    scan_id=scan_id,
                    tool_name=result.tool_name,
                    command=result.command_str,
                    stdout=result.stdout[:500_000] if result.stdout else None,
                    stderr=result.stderr[:100_000] if result.stderr else None,
                    exit_code=result.exit_code,
                    duration_ms=result.duration_ms,
                    status=result.status,
                    parsed_output=result.parsed_output or {},
                )
                db.add(tr)
                db.flush()

                findings = self._findings_from_attack_tool(scan_id, result)
                for f in findings:
                    db.add(f)
                db.commit()

                for f in findings:
                    db.refresh(f)
                    await self._emit(
                        scan_id,
                        status="running",
                        progress=progress_end,
                        current_tool=tool_name,
                        message=f"Finding: {f.title}",
                        finding={
                            "id": f.id,
                            "title": f.title,
                            "severity": f.severity,
                            "finding_type": f.finding_type,
                            "description": f.description,
                            "poc_curl": f.poc_curl,
                            "cvss_score": f.cvss_score,
                        },
                    )

                status_msg = result.status
                if result.status == "skipped":
                    status_msg = f"skipped ({result.skip_reason or 'not available'})"
                await self._emit(
                    scan_id,
                    status="running",
                    progress=progress_end,
                    current_tool=tool_name,
                    message=f"Finished {tool_name}: {status_msg}",
                    tool_result={
                        "tool_name": tool_name,
                        "status": result.status,
                        "duration_ms": result.duration_ms,
                        "parsed_summary": self._summarize_parsed(result),
                    },
                )

                scan.progress = progress_end
                db.commit()

            scan.status = "completed"
            scan.progress = 100.0
            scan.current_tool = None
            scan.completed_at = _utcnow()
            db.commit()
            await self._emit(
                scan_id,
                status="completed",
                progress=100,
                message="Attack Mode completed",
            )
        except asyncio.CancelledError:
            logger.info("Attack scan %s cancelled", scan_id)
            raise
        except Exception as exc:
            logger.exception("Attack scan %s failed", scan_id)
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "failed"
                scan.error_message = str(exc)[:1000]
                scan.completed_at = _utcnow()
                db.commit()
            await self._emit(
                scan_id,
                status="failed",
                progress=0,
                message=f"Attack failed: {exc}",
            )
        finally:
            db.close()
            self._tasks.pop(scan_id, None)

    def _summarize_parsed(self, result: ToolRunResult) -> dict[str, Any]:
        p = result.parsed_output or {}
        if result.tool_name == "subfinder":
            return {"subdomain_count": len(p.get("subdomains") or [])}
        if result.tool_name == "nmap":
            return {"open_ports": len(p.get("ports") or [])}
        if result.tool_name == "ffuf":
            return {"endpoint_count": len(p.get("endpoints") or [])}
        if result.tool_name == "whatweb":
            return {"tech_count": len(p.get("technologies") or [])}
        if result.tool_name in (
            "nuclei",
            "nuclei_exploit",
            "sqlmap",
            "dalfox",
            "hydra",
            "ssrfmap",
            "jwt_tool",
            "lfi",
            "cmdi",
            "file_upload",
            "idor",
        ):
            return {"finding_count": len(p.get("findings") or [])}
        if result.tool_name == "katana":
            return {"url_count": len(p.get("urls") or [])}
        return {}

    def _findings_from_attack_tool(
        self, scan_id: str, result: ToolRunResult
    ) -> list[Finding]:
        findings: list[Finding] = []
        p = result.parsed_output or {}

        if result.status == "skipped":
            # Prefer structured findings when the wrapper already explained the skip
            pre = p.get("findings") or []
            if pre:
                for item in pre:
                    sev = (item.get("severity") or "info").lower()
                    if sev not in SEVERITY_CVSS:
                        sev = "info"
                    findings.append(
                        Finding(
                            scan_id=scan_id,
                            title=item.get("title") or f"{result.tool_name} skipped",
                            severity=sev,
                            finding_type=item.get("finding_type") or "tool_status",
                            description=item.get("description")
                            or result.skip_reason
                            or "Tool not available",
                            raw_data={"tool": result.tool_name, "status": "skipped"},
                        )
                    )
                return findings
            findings.append(
                Finding(
                    scan_id=scan_id,
                    title=f"{result.tool_name} skipped",
                    severity="info",
                    finding_type="tool_status",
                    description=result.skip_reason or result.stderr or "Tool not available",
                    raw_data={"tool": result.tool_name, "status": "skipped"},
                )
            )
            return findings

        for item in p.get("findings") or []:
            sev = (item.get("severity") or "info").lower()
            if sev not in SEVERITY_CVSS:
                sev = "info"
            refs = item.get("references") or item.get("reference") or []
            if isinstance(refs, str):
                refs = [refs]
            cve = item.get("cve_id")
            if isinstance(cve, list):
                cve = cve[0] if cve else None
            cvss = item.get("cvss_score")
            if cvss is None:
                cvss = SEVERITY_CVSS.get(sev)
            findings.append(
                Finding(
                    scan_id=scan_id,
                    title=item.get("title") or f"{result.tool_name} finding",
                    severity=sev,
                    finding_type=item.get("finding_type") or result.tool_name,
                    description=item.get("description"),
                    poc_request=item.get("poc_request"),
                    poc_response=item.get("poc_response"),
                    poc_curl=item.get("poc_curl"),
                    remediation=item.get("remediation"),
                    references=list(refs)[:20],
                    cve_id=cve,
                    cvss_score=float(cvss) if cvss is not None else None,
                    raw_data=item.get("raw") or item,
                )
            )
        return findings

    def _findings_from_tool(self, scan_id: str, result: ToolRunResult) -> list[Finding]:
        findings: list[Finding] = []
        p = result.parsed_output or {}

        if result.status == "skipped":
            findings.append(
                Finding(
                    scan_id=scan_id,
                    title=f"{result.tool_name} skipped",
                    severity="info",
                    finding_type="tool_status",
                    description=result.skip_reason or result.stderr or "Tool not available",
                    raw_data={"tool": result.tool_name, "status": "skipped"},
                )
            )
            return findings

        if result.tool_name == "subfinder":
            for sub in p.get("subdomains") or []:
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        title=f"Subdomain: {sub}",
                        severity="info",
                        finding_type="subdomain",
                        description=f"Discovered subdomain via Subfinder: {sub}",
                        raw_data={"subdomain": sub},
                    )
                )

        elif result.tool_name == "nmap":
            for port in p.get("ports") or []:
                svc = port.get("service") or "unknown"
                product = " ".join(
                    filter(None, [port.get("product"), port.get("version")])
                )
                title = f"Open port {port['port']}/{port.get('protocol', 'tcp')} ({svc})"
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        title=title,
                        severity="info",
                        finding_type="open_port",
                        description=product or f"{svc} listening",
                        raw_data=port,
                    )
                )

        elif result.tool_name == "ffuf":
            for ep in p.get("endpoints") or []:
                url = ep.get("url") or "unknown"
                status = ep.get("status")
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        title=f"Path found: {url}",
                        severity="info",
                        finding_type="directory",
                        description=f"HTTP {status} — discovered by ffuf",
                        raw_data=ep,
                    )
                )

        elif result.tool_name == "whatweb":
            techs = p.get("technologies") or []
            if techs:
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        title=f"Technology stack: {', '.join(techs[:12])}",
                        severity="info",
                        finding_type="technology",
                        description=f"Detected {len(techs)} technologies via WhatWeb",
                        raw_data={"technologies": techs},
                    )
                )

        elif result.tool_name == "nuclei":
            for item in p.get("findings") or []:
                sev = (item.get("severity") or "info").lower()
                if sev not in ("info", "low", "medium", "high", "critical"):
                    sev = "info"
                # Soft-cap: Deep Scan should not promote exploit-grade — clamp high+
                if sev in ("high", "critical"):
                    sev = "medium"
                refs = item.get("reference") or []
                if isinstance(refs, str):
                    refs = [refs]
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        title=item.get("name") or "Nuclei finding",
                        severity=sev,
                        finding_type="vulnerability",
                        description=item.get("description") or item.get("matched_at"),
                        references=list(refs)[:20],
                        raw_data=item,
                    )
                )

        elif result.tool_name == "katana":
            urls = p.get("urls") or []
            # Cap individual crawl findings to avoid DB spam
            for url in urls[:100]:
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        title=f"Crawled: {url}",
                        severity="info",
                        finding_type="endpoint",
                        description="Discovered by Katana crawler (no form submission)",
                        raw_data={"url": url},
                    )
                )
            if len(urls) > 100:
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        title=f"+{len(urls) - 100} additional crawled URLs",
                        severity="info",
                        finding_type="endpoint",
                        description=f"Total crawled URLs: {len(urls)}",
                        raw_data={"url_count": len(urls)},
                    )
                )

        return findings


scanner_service = ScannerService()
