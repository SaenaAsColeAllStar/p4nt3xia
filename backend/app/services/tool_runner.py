"""Subprocess wrapper for pentest tools with graceful missing-tool handling."""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str], Awaitable[None] | None]


@dataclass
class ToolRunResult:
    tool_name: str
    command: list[str]
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    duration_ms: int = 0
    status: str = "completed"  # completed | failed | skipped
    parsed_output: dict = field(default_factory=dict)
    skip_reason: str | None = None

    @property
    def command_str(self) -> str:
        return " ".join(self.command)


class ToolRunner:
    """Runs external tools via asyncio subprocess."""

    def __init__(self, binary: str, tool_name: str | None = None):
        self.binary = binary
        self.tool_name = tool_name or binary

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    async def run(
        self,
        args: list[str],
        *,
        timeout: int = 300,
        cwd: str | None = None,
        on_stdout_line: ProgressCallback | None = None,
    ) -> ToolRunResult:
        cmd = [self.binary, *args]
        if not self.is_available():
            reason = f"Tool '{self.binary}' is not installed or not on PATH"
            logger.warning(reason)
            return ToolRunResult(
                tool_name=self.tool_name,
                command=cmd,
                stderr=reason,
                exit_code=None,
                status="skipped",
                skip_reason=reason,
            )

        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )
        except OSError as exc:
            return ToolRunResult(
                tool_name=self.tool_name,
                command=cmd,
                stderr=str(exc),
                exit_code=None,
                duration_ms=int((time.monotonic() - start) * 1000),
                status="failed",
            )

        stdout_chunks: list[str] = []
        stderr_chunks: list[str] = []

        async def _read_stream(stream: asyncio.StreamReader, chunks: list[str], is_stdout: bool) -> None:
            while True:
                line = await stream.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace")
                chunks.append(text)
                if is_stdout and on_stdout_line:
                    result = on_stdout_line(text.rstrip("\n"))
                    if asyncio.iscoroutine(result):
                        await result

        try:
            assert proc.stdout is not None and proc.stderr is not None
            await asyncio.wait_for(
                asyncio.gather(
                    _read_stream(proc.stdout, stdout_chunks, True),
                    _read_stream(proc.stderr, stderr_chunks, False),
                    proc.wait(),
                ),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ToolRunResult(
                tool_name=self.tool_name,
                command=cmd,
                stdout="".join(stdout_chunks),
                stderr="".join(stderr_chunks) + f"\nTimed out after {timeout}s",
                exit_code=-1,
                duration_ms=int((time.monotonic() - start) * 1000),
                status="failed",
            )

        duration_ms = int((time.monotonic() - start) * 1000)
        exit_code = proc.returncode if proc.returncode is not None else -1
        status = "completed" if exit_code == 0 else "failed"
        # Many scanners exit non-zero when findings exist; treat as completed if we got stdout
        if exit_code != 0 and stdout_chunks and self.tool_name in ("nuclei", "ffuf", "nmap"):
            status = "completed"

        return ToolRunResult(
            tool_name=self.tool_name,
            command=cmd,
            stdout="".join(stdout_chunks),
            stderr="".join(stderr_chunks),
            exit_code=exit_code,
            duration_ms=duration_ms,
            status=status,
        )
