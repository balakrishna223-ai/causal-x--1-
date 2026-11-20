import asyncio
from collections import defaultdict
from typing import Any, Dict, Set
from fastapi import WebSocket


class TenantWebSocketManager:
    """Manages authenticated tenant-scoped WebSocket connections for live dashboard updates."""

    def __init__(self) -> None:
        self._connections: Dict[str, Set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def connect(self, tenant_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections[tenant_id].add(websocket)

    async def disconnect(self, tenant_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            self._connections[tenant_id].discard(websocket)
            if not self._connections[tenant_id]:
                self._connections.pop(tenant_id, None)

    async def broadcast_to_tenant(self, tenant_id: str, event_type: str, data: Dict[str, Any]) -> None:
        async with self._lock:
            sockets = list(self._connections.get(tenant_id, set()))

        if not sockets:
            return

        message = {"type": event_type, "data": data}
        stale: list[WebSocket] = []
        for ws in sockets:
            try:
                await ws.send_json(message)
            except Exception:  # noqa: BLE001
                stale.append(ws)

        if stale:
            async with self._lock:
                for ws in stale:
                    self._connections[tenant_id].discard(ws)


ws_manager = TenantWebSocketManager()
