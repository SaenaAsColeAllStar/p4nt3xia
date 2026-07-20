"""Custom payload template builder CRUD + run."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.deps import RequireOperator, RequireViewer
from app.models.payload_template import PayloadTemplate
from app.models.user import User
from app.schemas.template import (
    TemplateCreate,
    TemplateOut,
    TemplateRunRequest,
    TemplateRunResult,
    TemplateUpdate,
)
from app.services.template_runner import run_template

router = APIRouter(prefix="/templates", tags=["templates"])

SEED_TEMPLATES = [
    {
        "name": "Reflected XSS probe",
        "category": "xss",
        "description": "Basic reflected XSS payloads in query parameter q",
        "method": "GET",
        "path_template": "/?q={{payload}}",
        "headers": {},
        "body_template": None,
        "payloads": [
            "<script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
            "'\"><svg/onload=alert(1)>",
        ],
        "match_status": [],
        "match_body_contains": ["<script>alert(1)</script>", "onerror=alert(1)", "onload=alert(1)"],
        "tags": ["xss", "reflected"],
    },
    {
        "name": "SQLi error-based probe",
        "category": "sqli",
        "description": "Classic quote / OR payloads on id parameter",
        "method": "GET",
        "path_template": "/?id={{payload}}",
        "headers": {},
        "body_template": None,
        "payloads": ["1'", "1\"", "1 OR 1=1--", "1' OR '1'='1"],
        "match_status": [],
        "match_body_contains": [
            "SQL syntax",
            "mysql_",
            "PostgreSQL",
            "ORA-",
            "sqlite3",
            "Unclosed quotation",
        ],
        "tags": ["sqli"],
    },
    {
        "name": "LFI path traversal",
        "category": "lfi",
        "description": "Common path traversal for file= / path= / page=",
        "method": "GET",
        "path_template": "/?file={{payload}}",
        "headers": {},
        "body_template": None,
        "payloads": [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
        ],
        "match_status": [],
        "match_body_contains": ["root:x:", "daemon:"],
        "tags": ["lfi"],
    },
]


def _ensure_seeds(db: Session) -> None:
    if db.query(PayloadTemplate).count() > 0:
        return
    for item in SEED_TEMPLATES:
        db.add(PayloadTemplate(**item))
    db.commit()


@router.get("", response_model=list[TemplateOut])
def list_templates(
    _user: RequireViewer,
    db: Session = Depends(get_db),
    category: str | None = None,
) -> list[PayloadTemplate]:
    _ensure_seeds(db)
    q = db.query(PayloadTemplate).order_by(PayloadTemplate.updated_at.desc())
    if category:
        q = q.filter(PayloadTemplate.category == category)
    return q.all()


@router.post("", response_model=TemplateOut, status_code=201)
def create_template(
    payload: TemplateCreate,
    user: RequireOperator,
    db: Session = Depends(get_db),
) -> PayloadTemplate:
    tpl = PayloadTemplate(
        **payload.model_dump(),
        created_by=user.id if isinstance(user, User) else None,
    )
    db.add(tpl)
    db.commit()
    db.refresh(tpl)
    return tpl


@router.get("/{template_id}", response_model=TemplateOut)
def get_template(
    template_id: str,
    _user: RequireViewer,
    db: Session = Depends(get_db),
) -> PayloadTemplate:
    tpl = db.query(PayloadTemplate).filter(PayloadTemplate.id == template_id).first()
    if not tpl:
        raise HTTPException(status_code=404, detail="Template not found")
    return tpl


@router.patch("/{template_id}", response_model=TemplateOut)
def update_template(
    template_id: str,
    payload: TemplateUpdate,
    _user: RequireOperator,
    db: Session = Depends(get_db),
) -> PayloadTemplate:
    tpl = db.query(PayloadTemplate).filter(PayloadTemplate.id == template_id).first()
    if not tpl:
        raise HTTPException(status_code=404, detail="Template not found")
    data = payload.model_dump(exclude_unset=True)
    for k, v in data.items():
        setattr(tpl, k, v)
    db.commit()
    db.refresh(tpl)
    return tpl


@router.delete("/{template_id}", status_code=204)
def delete_template(
    template_id: str,
    _user: RequireOperator,
    db: Session = Depends(get_db),
) -> None:
    tpl = db.query(PayloadTemplate).filter(PayloadTemplate.id == template_id).first()
    if not tpl:
        raise HTTPException(status_code=404, detail="Template not found")
    db.delete(tpl)
    db.commit()


@router.post("/{template_id}/run", response_model=TemplateRunResult)
async def run_template_endpoint(
    template_id: str,
    payload: TemplateRunRequest,
    _user: RequireOperator,
    db: Session = Depends(get_db),
) -> TemplateRunResult:
    tpl = db.query(PayloadTemplate).filter(PayloadTemplate.id == template_id).first()
    if not tpl:
        raise HTTPException(status_code=404, detail="Template not found")
    try:
        return await run_template(tpl, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
