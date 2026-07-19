"""Scan routes — start Deep Scan, fetch results, cancel."""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.models.scan import Scan
from app.schemas.scan import DeepScanRequest, ScanOut, ScanWithDetails
from app.services.report import scan_to_json
from app.services.scanner import scanner_service

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("", response_model=list[ScanOut])
def list_scans(limit: int = 50, db: Session = Depends(get_db)) -> list[Scan]:
    return (
        db.query(Scan)
        .options(joinedload(Scan.target))
        .order_by(Scan.started_at.desc().nullslast(), Scan.id.desc())
        .limit(min(limit, 200))
        .all()
    )


@router.post("/deep", response_model=ScanOut, status_code=201)
async def start_deep_scan(
    payload: DeepScanRequest, db: Session = Depends(get_db)
) -> Scan:
    try:
        scan = scanner_service.create_deep_scan(db, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    scanner_service.start_scan(scan.id)
    db.refresh(scan)
    # Reload with target
    scan = (
        db.query(Scan)
        .options(joinedload(Scan.target))
        .filter(Scan.id == scan.id)
        .first()
    )
    return scan


@router.get("/{scan_id}", response_model=ScanWithDetails)
def get_scan(scan_id: str, db: Session = Depends(get_db)) -> Scan:
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


@router.post("/{scan_id}/cancel", response_model=ScanOut)
async def cancel_scan(scan_id: str, db: Session = Depends(get_db)) -> Scan:
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
def get_scan_report(scan_id: str, db: Session = Depends(get_db)) -> JSONResponse:
    data = scan_to_json(db, scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse(content=data)
