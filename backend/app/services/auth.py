"""JWT + password helpers for multi-user auth."""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.config import settings
from app.models.user import User

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ROLE_RANK = {"viewer": 1, "operator": 2, "admin": 3}


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(user: User) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {
        "sub": user.id,
        "username": user.username,
        "role": user.role,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict[str, Any] | None:
    try:
        return jwt.decode(
            token, settings.jwt_secret, algorithms=[settings.jwt_algorithm]
        )
    except JWTError:
        return None


def role_at_least(role: str, required: str) -> bool:
    return ROLE_RANK.get(role, 0) >= ROLE_RANK.get(required, 99)


def bootstrap_admin(db: Session) -> User | None:
    """Create bootstrap admin from env if no users exist and credentials set."""
    existing = db.query(User).count()
    if existing > 0:
        return None
    username = (settings.bootstrap_admin_user or "").strip()
    password = settings.bootstrap_admin_password or ""
    if not username or not password:
        if settings.auth_enabled:
            logger.warning(
                "Auth enabled but no users and no P4NT3XIA_BOOTSTRAP_ADMIN_* — "
                "register the first admin via POST /api/auth/register"
            )
        return None
    user = User(
        username=username,
        email=settings.bootstrap_admin_email,
        hashed_password=hash_password(password),
        role="admin",
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info("Bootstrapped admin user %s", username)
    return user


def ensure_jwt_secret() -> None:
    """Warn if using the insecure default secret in production-ish setups."""
    if settings.jwt_secret == "change-me-p4nt3xia-dev-secret":
        logger.warning(
            "Using default JWT secret — set P4NT3XIA_JWT_SECRET for any shared deployment"
        )


def generate_dev_secret() -> str:
    return secrets.token_urlsafe(32)


def fingerprint_token(token: str) -> str:
    return hmac.new(
        settings.jwt_secret.encode(), token.encode(), hashlib.sha256
    ).hexdigest()[:16]
