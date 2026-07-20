"""Frida Android analysis schemas."""

from pydantic import BaseModel, Field


class FridaDeviceOut(BaseModel):
    id: str
    name: str
    type: str


class FridaAppOut(BaseModel):
    identifier: str
    name: str
    pid: int | None = None


class FridaScriptRequest(BaseModel):
    device_id: str = Field(default="usb")
    target: str = Field(
        description="Package name (spawn) or PID (attach)",
        min_length=1,
        max_length=256,
    )
    spawn: bool = True
    script: str = Field(
        min_length=1,
        max_length=200_000,
        description="Frida JavaScript instrumentation script",
    )
    timeout: int = Field(default=30, ge=5, le=300)
    authorized: bool = False


class FridaRunResult(BaseModel):
    status: str
    device_id: str
    target: str
    messages: list[str]
    stdout: str | None = None
    stderr: str | None = None
    skip_reason: str | None = None
