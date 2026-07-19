"""P4NT3XIA FastAPI application entrypoint."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db
from app.routers import dashboard, scans, targets, websocket

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title=settings.app_name,
    description="Personal pentest web platform — Phase 1 MVP (Deep Scan)",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

api = settings.api_prefix
app.include_router(dashboard.router, prefix=api)
app.include_router(targets.router, prefix=api)
app.include_router(scans.router, prefix=api)
app.include_router(websocket.router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "app": settings.app_name}
