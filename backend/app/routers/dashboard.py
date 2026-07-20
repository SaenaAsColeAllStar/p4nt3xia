"""Dashboard and scan history routes."""

from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.deps import RequireViewer
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.target import Target
from app.schemas.scan import DashboardStats, ScanOut

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard", response_model=DashboardStats)
def get_dashboard(
    _user: RequireViewer,
    db: Session = Depends(get_db),
) -> DashboardStats:
    total_scans = db.query(Scan).count()
    active_targets = db.query(Target).count()
    running_scans = db.query(Scan).filter(Scan.status == "running").count()

    # Count non-info findings as "vulnerabilities" for the summary card
    vuln_q = db.query(Finding).filter(Finding.severity.in_(["low", "medium", "high", "critical"]))
    vulnerabilities_found = vuln_q.count()

    all_findings = db.query(Finding.severity).all()
    severity_breakdown = dict(Counter(s for (s,) in all_findings))

    recent = (
        db.query(Scan)
        .options(joinedload(Scan.target))
        .order_by(Scan.started_at.desc().nullslast(), Scan.id.desc())
        .limit(10)
        .all()
    )

    return DashboardStats(
        total_scans=total_scans,
        active_targets=active_targets,
        vulnerabilities_found=vulnerabilities_found,
        running_scans=running_scans,
        severity_breakdown=severity_breakdown,
        recent_scans=[ScanOut.model_validate(s) for s in recent],
    )
