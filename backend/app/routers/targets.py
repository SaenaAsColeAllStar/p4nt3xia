"""Target library routes."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.target import Target
from app.schemas.target import TargetCreate, TargetOut
from app.services.target_utils import is_valid_target

router = APIRouter(prefix="/targets", tags=["targets"])


@router.get("", response_model=list[TargetOut])
def list_targets(db: Session = Depends(get_db)) -> list[Target]:
    return db.query(Target).order_by(Target.created_at.desc()).all()


@router.post("", response_model=TargetOut, status_code=201)
def create_target(payload: TargetCreate, db: Session = Depends(get_db)) -> Target:
    if not is_valid_target(payload.value):
        raise HTTPException(status_code=400, detail="Invalid target format")
    existing = db.query(Target).filter(Target.value == payload.value.strip()).first()
    if existing:
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


@router.get("/{target_id}", response_model=TargetOut)
def get_target(target_id: str, db: Session = Depends(get_db)) -> Target:
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.delete("/{target_id}", status_code=204)
def delete_target(target_id: str, db: Session = Depends(get_db)) -> None:
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    db.delete(target)
    db.commit()
