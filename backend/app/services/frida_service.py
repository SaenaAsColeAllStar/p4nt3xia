"""Frida integration for Android dynamic analysis.

Missing frida/frida-tools or no device → status=skipped (never crash orchestrator).
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from typing import Any

from app.config import settings
from app.schemas.frida import FridaAppOut, FridaDeviceOut, FridaRunResult, FridaScriptRequest

logger = logging.getLogger(__name__)


def frida_available() -> bool:
    try:
        import frida  # noqa: F401

        return True
    except ImportError:
        return shutil.which(settings.frida_path) is not None or shutil.which("frida") is not None


def list_devices() -> list[FridaDeviceOut]:
    if not frida_available():
        return []
    try:
        import frida

        devices = frida.enumerate_devices()
        out: list[FridaDeviceOut] = []
        for d in devices:
            dtype = getattr(d, "type", None) or "unknown"
            if hasattr(dtype, "name"):
                dtype = dtype.name.lower()
            out.append(FridaDeviceOut(id=d.id, name=d.name, type=str(dtype)))
        return out
    except Exception as exc:
        logger.warning("frida enumerate_devices failed: %s", exc)
        return []


def list_apps(device_id: str = "usb") -> list[FridaAppOut]:
    if not frida_available():
        return []
    try:
        import frida

        device = _get_device(frida, device_id)
        apps = device.enumerate_applications()
        return [
            FridaAppOut(
                identifier=a.identifier,
                name=a.name,
                pid=getattr(a, "pid", None) or None,
            )
            for a in apps
        ]
    except Exception as exc:
        logger.warning("frida enumerate_applications failed: %s", exc)
        return []


def _get_device(frida: Any, device_id: str) -> Any:
    if device_id in ("usb", "device"):
        return frida.get_usb_device(timeout=5)
    if device_id in ("local",):
        return frida.get_local_device()
    return frida.get_device(device_id, timeout=5)


async def run_script(req: FridaScriptRequest) -> FridaRunResult:
    if not req.authorized:
        return FridaRunResult(
            status="failed",
            device_id=req.device_id,
            target=req.target,
            messages=[],
            stderr="authorized=true required for Frida instrumentation",
            skip_reason=None,
        )

    if not frida_available():
        return FridaRunResult(
            status="skipped",
            device_id=req.device_id,
            target=req.target,
            messages=[],
            skip_reason="frida / frida-tools not installed in this environment",
        )

    return await asyncio.to_thread(_run_script_sync, req)


def _run_script_sync(req: FridaScriptRequest) -> FridaRunResult:
    messages: list[str] = []
    try:
        import frida

        device = _get_device(frida, req.device_id)
        session = None
        pid = None
        if req.spawn and not req.target.isdigit():
            pid = device.spawn([req.target])
            session = device.attach(pid)
        elif req.target.isdigit():
            session = device.attach(int(req.target))
        else:
            session = device.attach(req.target)

        def on_message(message: dict, data: Any) -> None:  # noqa: ARG001
            if message.get("type") == "send":
                messages.append(str(message.get("payload")))
            elif message.get("type") == "error":
                messages.append(
                    f"error: {message.get('description') or message.get('stack') or message}"
                )
            else:
                messages.append(str(message))

        script = session.create_script(req.script)
        script.on("message", on_message)
        script.load()
        if pid is not None:
            device.resume(pid)

        # Collect for timeout seconds
        import time

        deadline = time.time() + req.timeout
        while time.time() < deadline:
            time.sleep(0.25)

        try:
            script.unload()
        except Exception:
            pass
        try:
            session.detach()
        except Exception:
            pass

        return FridaRunResult(
            status="completed",
            device_id=req.device_id,
            target=req.target,
            messages=messages[:500],
            stdout="\n".join(messages[:500]),
        )
    except Exception as exc:
        logger.exception("Frida run failed")
        err = str(exc)
        # No device is a skip, not a hard crash of the platform
        status = "skipped" if "device" in err.lower() or "timed out" in err.lower() else "failed"
        return FridaRunResult(
            status=status,
            device_id=req.device_id,
            target=req.target,
            messages=messages,
            stderr=err[:4000],
            skip_reason=err if status == "skipped" else None,
        )


# Sample scripts for the UI
SAMPLE_SCRIPTS: dict[str, str] = {
    "android_ssl_bypass": """\
Java.perform(function () {
  var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
  TrustManagerImpl.verifyChain.implementation = function () {
    send('ssl_pinning_bypass: verifyChain hooked');
    return arguments[0];
  };
  send('android_ssl_bypass loaded');
});
""",
    "android_root_bypass_stub": """\
Java.perform(function () {
  send('root_bypass_stub: attach OK — customize for your packaging');
  var File = Java.use('java.io.File');
  File.exists.implementation = function () {
    var path = this.getAbsolutePath();
    if (path.indexOf('su') !== -1 || path.indexOf('Magisk') !== -1) {
      send('hid path check: ' + path);
      return false;
    }
    return this.exists();
  };
});
""",
    "enumerate_classes": """\
Java.perform(function () {
  var count = 0;
  Java.enumerateLoadedClasses({
    onMatch: function (name) {
      if (count < 50) { send(name); }
      count++;
    },
    onComplete: function () { send('total_classes=' + count); }
  });
});
""",
}
