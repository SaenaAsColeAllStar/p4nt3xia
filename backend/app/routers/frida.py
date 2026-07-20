"""Frida Android dynamic analysis routes."""

from fastapi import APIRouter, HTTPException

from app.deps import RequireOperator, RequireViewer
from app.schemas.frida import (
    FridaAppOut,
    FridaDeviceOut,
    FridaRunResult,
    FridaScriptRequest,
)
from app.services import frida_service

router = APIRouter(prefix="/frida", tags=["frida"])


@router.get("/status")
def frida_status(_user: RequireViewer) -> dict:
    available = frida_service.frida_available()
    devices = frida_service.list_devices() if available else []
    return {
        "available": available,
        "device_count": len(devices),
        "sample_scripts": list(frida_service.SAMPLE_SCRIPTS.keys()),
    }


@router.get("/devices", response_model=list[FridaDeviceOut])
def devices(_user: RequireViewer) -> list[FridaDeviceOut]:
    if not frida_service.frida_available():
        return []
    return frida_service.list_devices()


@router.get("/apps", response_model=list[FridaAppOut])
def apps(device_id: str = "usb", _user: RequireViewer = None) -> list[FridaAppOut]:
    return frida_service.list_apps(device_id)


@router.get("/samples")
def samples(_user: RequireViewer) -> dict[str, str]:
    return frida_service.SAMPLE_SCRIPTS


@router.post("/run", response_model=FridaRunResult)
async def run_script(
    payload: FridaScriptRequest,
    _user: RequireOperator,
) -> FridaRunResult:
    if not payload.authorized:
        raise HTTPException(
            status_code=400,
            detail="authorized=true required — only instrument apps you own / have permission to test",
        )
    return await frida_service.run_script(payload)
