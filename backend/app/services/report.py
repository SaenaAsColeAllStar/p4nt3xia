"""Report generation stub — full PDF/HTML in later phases."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.scan import Scan


def scan_to_json(db: Session, scan_id: str) -> dict[str, Any] | None:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return None
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    severity_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
    return {
        "scan_id": scan.id,
        "mode": scan.mode,
        "status": scan.status,
        "target": scan.target.value if scan.target else None,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "summary": {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
        },
        "findings": [
            {
                "title": f.title,
                "severity": f.severity,
                "type": f.finding_type,
                "description": f.description,
                "cve_id": f.cve_id,
                "cvss_score": f.cvss_score,
                "remediation": f.remediation,
                "references": f.references,
            }
            for f in findings
        ],
    }
