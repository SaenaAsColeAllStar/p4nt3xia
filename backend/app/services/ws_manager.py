"""WebSocket connection manager for scan progress broadcasting."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import WebSocket
from starlette.websockets import WebSocketDisconnect, WebSocketState

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[str, set[WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, scan_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections.setdefault(scan_id, set()).add(websocket)
        logger.info("WebSocket connected for scan %s", scan_id)

    async def disconnect(self, scan_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            conns = self._connections.get(scan_id)
            if conns and websocket in conns:
                conns.discard(websocket)
            if conns is not None and not conns:
                self._connections.pop(scan_id, None)

    async def broadcast(self, scan_id: str, payload: dict[str, Any]) -> None:
        async with self._lock:
            conns = list(self._connections.get(scan_id, set()))
        dead: list[WebSocket] = []
        for ws in conns:
            try:
                if ws.client_state == WebSocketState.CONNECTED:
                    await ws.send_json(payload)
            except (WebSocketDisconnect, RuntimeError) as exc:
                logger.debug("WS send failed: %s", exc)
                dead.append(ws)
        for ws in dead:
            await self.disconnect(scan_id, ws)


ws_manager = ConnectionManager()
