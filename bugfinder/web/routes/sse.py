from __future__ import annotations

import asyncio
import json
import time

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

router = APIRouter()

_scan_progress: dict[str, dict] = {}


def update_scan_progress(scan_id: str, data: dict):
    _scan_progress[scan_id] = {**_scan_progress.get(scan_id, {}), **data, "timestamp": time.time()}


def get_scan_progress(scan_id: str) -> dict | None:
    return _scan_progress.get(scan_id)


@router.get("/stream/{scan_id}")
async def stream_scan(scan_id: str):
    async def event_generator():
        while True:
            progress = get_scan_progress(scan_id)
            if progress:
                yield f"data: {json.dumps(progress)}\n\n"
                if progress.get("status") in ("completed", "failed", "cancelled"):
                    break
            else:
                yield f"data: {json.dumps({'scan_id': scan_id, 'status': 'pending', 'progress': 0})}\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/stream")
async def stream_all():
    async def event_generator():
        while True:
            if _scan_progress:
                yield f"data: {json.dumps(list(_scan_progress.values()))}\n\n"
            else:
                yield "data: []\n\n"
            await asyncio.sleep(2)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
