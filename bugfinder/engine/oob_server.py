from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime

import httpx

logger = logging.getLogger(__name__)


@dataclass
class OOBCallback:
    id: str
    scan_id: int
    type: str
    payload: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    received: datetime | None = None
    data: dict | None = None


class OOBServer:
    def __init__(self, interactsh_url: str = "https://oast.fun"):
        self.interactsh_url = interactsh_url
        self._callbacks: list[OOBCallback] = []
        self._session_id: str = ""
        self._polling = False

    async def start_polling(self):
        self._polling = True
        logger.info("OOB polling started for session: %s", self._session_id)

    async def stop_polling(self):
        self._polling = False
        logger.info("OOB polling stopped")

    async def poll_callbacks(self, scan_id: int) -> list[OOBCallback]:
        await asyncio.sleep(2)
        return [cb for cb in self._callbacks if cb.scan_id == scan_id]

    def register_callback(self, scan_id: int, cb_type: str, payload: str) -> str:
        cb_id = str(uuid.uuid4())[:8]
        callback = OOBCallback(id=cb_id, scan_id=scan_id, type=cb_type, payload=payload)
        self._callbacks.append(callback)
        return cb_id

    async def check_interactsh(self) -> list[dict]:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"{self.interactsh_url}/poll/{self._session_id}",
                    headers={"User-Agent": "BugFinder/0.2.0"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    interactions = data.get("interactions", [])
                    for interaction in interactions:
                        cb = OOBCallback(
                            id=str(uuid.uuid4()),
                            scan_id=0,
                            type=interaction.get("type", "unknown"),
                            payload=interaction.get("raw", ""),
                            received=datetime.utcnow(),
                            data=interaction,
                        )
                        self._callbacks.append(cb)
                    return interactions
        except Exception as e:
            logger.debug("Interact.sh poll failed: %s", e)
        return []

    def clear_callbacks(self, scan_id: int | None = None):
        if scan_id:
            self._callbacks = [cb for cb in self._callbacks if cb.scan_id != scan_id]
        else:
            self._callbacks.clear()


oob_server = OOBServer()
