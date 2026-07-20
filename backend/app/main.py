"""P4NT3XIA FastAPI application entrypoint."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db
from app.routers import api_mode, auth, dashboard, frida, scans, targets, templates, websocket

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
    description="Personal pentest web platform — Deep Scan + Attack Mode + Phase 4",
    version="0.4.0",
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
app.include_router(auth.router, prefix=api)
app.include_router(frida.router, prefix=api)
app.include_router(api_mode.router, prefix=api)
app.include_router(templates.router, prefix=api)
app.include_router(websocket.router)


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "app": settings.app_name,
        "version": "0.4.0",
        "auth_enabled": settings.auth_enabled,
    }
