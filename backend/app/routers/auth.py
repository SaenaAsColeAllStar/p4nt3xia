"""Auth routes — login, register, me, user admin."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.deps import RequireAdmin, RequireViewer, get_optional_user
from app.models.user import User
from app.schemas.auth import (
    AuthStatusOut,
    TokenOut,
    UserCreate,
    UserLogin,
    UserOut,
    UserUpdate,
)
from app.services.auth import (
    create_access_token,
    hash_password,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/status", response_model=AuthStatusOut)
def auth_status(
    user: User | None = Depends(get_optional_user),
) -> AuthStatusOut:
    return AuthStatusOut(
        auth_enabled=settings.auth_enabled,
        user=UserOut.model_validate(user) if user else None,
    )


@router.post("/register", response_model=UserOut, status_code=201)
def register(payload: UserCreate, db: Session = Depends(get_db)) -> User:
    count = db.query(User).count()
    # First user may bootstrap as admin; afterward require auth_enabled=false OR admin
    if count > 0 and settings.auth_enabled:
        raise HTTPException(
            status_code=403,
            detail="Registration closed when auth is enabled — ask an admin to create users",
        )
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if payload.email and db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already taken")

    role = payload.role
    if count == 0:
        role = "admin"
    elif settings.auth_enabled:
        role = "operator"

    user = User(
        username=payload.username.strip(),
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenOut)
def login(payload: UserLogin, db: Session = Depends(get_db)) -> TokenOut:
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    token = create_access_token(user)
    return TokenOut(access_token=token, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
def me(user: RequireViewer) -> User:
    if user is None:
        # auth disabled and no token
        raise HTTPException(
            status_code=400,
            detail="No session — auth is disabled or not logged in",
        )
    return user


@router.get("/users", response_model=list[UserOut])
def list_users(
    _admin: RequireAdmin,
    db: Session = Depends(get_db),
) -> list[User]:
    return db.query(User).order_by(User.created_at.asc()).all()


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(
    payload: UserCreate,
    _admin: RequireAdmin,
    db: Session = Depends(get_db),
) -> User:
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    user = User(
        username=payload.username.strip(),
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: str,
    payload: UserUpdate,
    _admin: RequireAdmin,
    db: Session = Depends(get_db),
) -> User:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if payload.email is not None:
        user.email = payload.email
    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active
    if payload.password:
        user.hashed_password = hash_password(payload.password)
    db.commit()
    db.refresh(user)
    return user
