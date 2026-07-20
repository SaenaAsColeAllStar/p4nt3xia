"""Scan routes — Deep Scan, Attack Mode, reports, cancel."""

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.deps import RequireOperator, RequireViewer
from app.models.finding import Finding
from app.models.scan import Scan
from app.schemas.finding import FindingOut
from app.schemas.scan import (
    AttackScanRequest,
    DeepScanRequest,
    ScanOut,
    ScanWithDetails,
)
from app.services.report import scan_to_html, scan_to_json, scan_to_markdown, scan_to_pdf
from app.services.scanner import scanner_service

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("", response_model=list[ScanOut])
def list_scans(
    _user: RequireViewer,
    limit: int = 50,
    db: Session = Depends(get_db),
) -> list[Scan]:
    return (
        db.query(Scan)
        .options(joinedload(Scan.target))
        .order_by(Scan.started_at.desc().nullslast(), Scan.id.desc())
        .limit(min(limit, 200))
        .all()
    )


@router.post("/deep", response_model=ScanOut, status_code=201)
async def start_deep_scan(
    payload: DeepScanRequest,
    _user: RequireOperator,
    db: Session = Depends(get_db),
) -> Scan:
    try:
        scan = scanner_service.create_deep_scan(db, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    scanner_service.start_scan(scan.id, mode="deep_scan")
    scan = (
        db.query(Scan)
        .options(joinedload(Scan.target))
        .filter(Scan.id == scan.id)
        .first()
    )
    return scan


@router.post("/attack", response_model=ScanOut, status_code=201)
async def start_attack_scan(
    payload: AttackScanRequest,
    _user: RequireOperator,
    db: Session = Depends(get_db),
) -> Scan:
    try:
        scan = scanner_service.create_attack_scan(db, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    scanner_service.start_scan(scan.id, mode="attack")
    scan = (
        db.query(Scan)
        .options(joinedload(Scan.target))
        .filter(Scan.id == scan.id)
        .first()
    )
    return scan


@router.get("/{scan_id}", response_model=ScanWithDetails)
def get_scan(
    scan_id: str, _user: RequireViewer, db: Session = Depends(get_db)
) -> Scan:
    scan = (
        db.query(Scan)
        .options(
            joinedload(Scan.target),
            joinedload(Scan.findings),
            joinedload(Scan.tool_results),
        )
        .filter(Scan.id == scan_id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/findings/{finding_id}", response_model=FindingOut)
def get_finding(
    scan_id: str,
    finding_id: str,
    _user: RequireViewer,
    db: Session = Depends(get_db),
) -> Finding:
    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id, Finding.scan_id == scan_id)
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.post("/{scan_id}/cancel", response_model=ScanOut)
async def cancel_scan(
    scan_id: str, _user: RequireOperator, db: Session = Depends(get_db)
) -> Scan:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    cancelled = await scanner_service.cancel_scan(scan_id)
    if not cancelled and scan.status not in ("running", "pending"):
        raise HTTPException(status_code=400, detail="Scan is not running")
    db.refresh(scan)
    scan = (
        db.query(Scan)
        .options(joinedload(Scan.target))
        .filter(Scan.id == scan_id)
        .first()
    )
    return scan


@router.get("/{scan_id}/report")
def get_scan_report(
    scan_id: str,
    _user: RequireViewer,
    format: str = Query(default="json", pattern="^(json|html|pdf|markdown|md)$"),
    db: Session = Depends(get_db),
):
    if format == "html":
        content = scan_to_html(db, scan_id)
        if content is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        return HTMLResponse(content=content)
    if format in ("markdown", "md"):
        content = scan_to_markdown(db, scan_id)
        if content is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        return PlainTextResponse(content=content, media_type="text/markdown")
    if format == "pdf":
        try:
            pdf_bytes = scan_to_pdf(db, scan_id)
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        if pdf_bytes is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="p4nt3xia-{scan_id}.pdf"'
            },
        )
    data = scan_to_json(db, scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse(content=data)
