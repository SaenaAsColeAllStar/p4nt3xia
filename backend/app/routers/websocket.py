"""WebSocket endpoint for real-time scan progress."""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.scan import Scan
from app.services.ws_manager import ws_manager

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: str) -> None:
    db: Session = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            await websocket.close(code=4404)
            return
        # Send current snapshot immediately after connect
        await ws_manager.connect(scan_id, websocket)
        await websocket.send_json(
            {
                "scan_id": scan_id,
                "status": scan.status,
                "progress": scan.progress,
                "current_tool": scan.current_tool,
                "message": f"Connected — scan status: {scan.status}",
            }
        )
        # Keep alive until client disconnects
        while True:
            # Client may send pings; we ignore payload
            await websocket.receive_text()
    except WebSocketDisconnect:
        await ws_manager.disconnect(scan_id, websocket)
    finally:
        db.close()
