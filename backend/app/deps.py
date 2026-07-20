"""FastAPI dependencies for optional JWT auth and role checks."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.services.auth import decode_token, role_at_least

bearer_scheme = HTTPBearer(auto_error=False)


def get_optional_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(bearer_scheme)
    ] = None,
    db: Session = Depends(get_db),
) -> User | None:
    if credentials is None or not credentials.credentials:
        return None
    payload = decode_token(credentials.credentials)
    if not payload or payload.get("type") != "access":
        return None
    user_id = payload.get("sub")
    if not user_id:
        return None
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        return None
    return user


def get_current_user(
    user: Annotated[User | None, Depends(get_optional_user)],
) -> User | None:
    """When auth is disabled, return None (anonymous OK). When enabled, require user."""
    if not settings.auth_enabled:
        return user
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_role(min_role: str):
    """Dependency factory: when auth enabled, enforce role. When disabled, allow."""

    def _dep(
        user: Annotated[User | None, Depends(get_current_user)],
    ) -> User | None:
        if not settings.auth_enabled:
            return user
        assert user is not None
        if not role_at_least(user.role, min_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role {min_role} or higher (have {user.role})",
            )
        return user

    return _dep


RequireViewer = Annotated[User | None, Depends(require_role("viewer"))]
RequireOperator = Annotated[User | None, Depends(require_role("operator"))]
RequireAdmin = Annotated[User | None, Depends(require_role("admin"))]
