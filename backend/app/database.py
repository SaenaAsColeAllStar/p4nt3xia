"""Database engine and session management."""

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

if settings.database_url:
    DATABASE_URL = settings.database_url
else:
    DATABASE_URL = f"sqlite:///{DATA_DIR / 'p4nt3xia.db'}"

_connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    _connect_args = {"check_same_thread": False}

engine = create_engine(
    DATABASE_URL,
    connect_args=_connect_args,
    echo=False,
    pool_pre_ping=True if not DATABASE_URL.startswith("sqlite") else False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from app import models  # noqa: F401
    from app.services.auth import bootstrap_admin, ensure_jwt_secret

    Base.metadata.create_all(bind=engine)
    ensure_jwt_secret()
    db = SessionLocal()
    try:
        bootstrap_admin(db)
    finally:
        db.close()
