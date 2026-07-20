"""Target library routes — CRUD with scan history polish."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.deps import RequireOperator, RequireViewer
from app.models.scan import Scan
from app.models.target import Target
from app.schemas.target import TargetCreate, TargetOut, TargetUpdate
from app.services.target_utils import is_valid_target

router = APIRouter(prefix="/targets", tags=["targets"])


class TargetWithStats(TargetOut):
    scan_count: int = 0
    last_scan_at: datetime | None = None
    last_scan_mode: str | None = None
    last_scan_status: str | None = None


@router.get("", response_model=list[TargetWithStats])
def list_targets(
    _user: RequireViewer, db: Session = Depends(get_db)
) -> list[TargetWithStats]:
    targets = db.query(Target).order_by(Target.created_at.desc()).all()
    results: list[TargetWithStats] = []
    for t in targets:
        scans = (
            db.query(Scan)
            .filter(Scan.target_id == t.id)
            .order_by(Scan.started_at.desc().nullslast(), Scan.id.desc())
            .all()
        )
        last = scans[0] if scans else None
        results.append(
            TargetWithStats(
                id=t.id,
                value=t.value,
                type=t.type,
                created_at=t.created_at,
                tags=t.tags or [],
                notes=t.notes,
                scan_count=len(scans),
                last_scan_at=last.started_at if last else None,
                last_scan_mode=last.mode if last else None,
                last_scan_status=last.status if last else None,
            )
        )
    return results


@router.post("", response_model=TargetOut, status_code=201)
def create_target(
    payload: TargetCreate, _user: RequireOperator, db: Session = Depends(get_db)
) -> Target:
    if not is_valid_target(payload.value):
        raise HTTPException(status_code=400, detail="Invalid target format")
    existing = db.query(Target).filter(Target.value == payload.value.strip()).first()
    if existing:
        # Update tags/notes if provided on re-save
        if payload.tags:
            existing.tags = payload.tags
        if payload.notes is not None:
            existing.notes = payload.notes
        if payload.type:
            existing.type = payload.type
        db.commit()
        db.refresh(existing)
        return existing
    target = Target(
        value=payload.value.strip(),
        type=payload.type,
        tags=payload.tags,
        notes=payload.notes,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


@router.get("/{target_id}", response_model=TargetWithStats)
def get_target(
    target_id: str, _user: RequireViewer, db: Session = Depends(get_db)
) -> TargetWithStats:
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    scans = (
        db.query(Scan)
        .filter(Scan.target_id == target.id)
        .order_by(Scan.started_at.desc().nullslast(), Scan.id.desc())
        .all()
    )
    last = scans[0] if scans else None
    return TargetWithStats(
        id=target.id,
        value=target.value,
        type=target.type,
        created_at=target.created_at,
        tags=target.tags or [],
        notes=target.notes,
        scan_count=len(scans),
        last_scan_at=last.started_at if last else None,
        last_scan_mode=last.mode if last else None,
        last_scan_status=last.status if last else None,
    )


@router.get("/{target_id}/scans", response_model=list)
def list_target_scans(
    target_id: str, _user: RequireViewer, db: Session = Depends(get_db)
):
    from app.schemas.scan import ScanOut

    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    scans = (
        db.query(Scan)
        .options(joinedload(Scan.target))
        .filter(Scan.target_id == target_id)
        .order_by(Scan.started_at.desc().nullslast(), Scan.id.desc())
        .all()
    )
    return [ScanOut.model_validate(s) for s in scans]


@router.patch("/{target_id}", response_model=TargetOut)
def update_target(
    target_id: str,
    payload: TargetUpdate,
    _user: RequireOperator,
    db: Session = Depends(get_db),
) -> Target:
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    data = payload.model_dump(exclude_unset=True)
    if "value" in data:
        if not is_valid_target(data["value"]):
            raise HTTPException(status_code=400, detail="Invalid target format")
        data["value"] = data["value"].strip()
    for key, value in data.items():
        setattr(target, key, value)
    db.commit()
    db.refresh(target)
    return target


@router.delete("/{target_id}", status_code=204)
def delete_target(
    target_id: str, _user: RequireOperator, db: Session = Depends(get_db)
) -> None:
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    db.delete(target)
    db.commit()
