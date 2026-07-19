from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from bugfinder.web.auth import get_current_user

router = APIRouter()


class RepeaterRequest(BaseModel):
    capture_id: str | None = None
    method: str = "GET"
    url: str = ""
    headers: str = ""
    body: str = ""


class RepeaterResponse(BaseModel):
    status_code: int
    headers: dict[str, str]
    body: str
    duration_ms: int
    error: str | None = None


@router.get("/proxy/history")
async def proxy_history(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    host: str | None = Query(None),
    user: str = Depends(get_current_user),
):
    from bugfinder.proxy.capture import ProxyCaptureStore

    store = ProxyCaptureStore()
    return await store.get_history(limit=limit, offset=offset, host=host)


@router.get("/proxy/capture/{capture_id}")
async def proxy_capture_detail(capture_id: str, user: str = Depends(get_current_user)):
    from bugfinder.proxy.capture import ProxyCaptureStore

    store = ProxyCaptureStore()
    detail = await store.get_detail(capture_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Capture not found")
    return detail


@router.post("/proxy/repeater", response_model=RepeaterResponse)
async def proxy_repeater(req: RepeaterRequest, user: str = Depends(get_current_user)):
    from bugfinder.proxy.repeater import Repeater

    repeater = Repeater()

    if req.capture_id:
        from bugfinder.proxy.capture import ProxyCaptureStore

        store = ProxyCaptureStore()
        capture = await store.get_detail(req.capture_id)
        if capture:
            result = await repeater.repeat_capture(capture)
            return RepeaterResponse(
                status_code=result.status_code,
                headers=result.headers,
                body=result.body[:50000],
                duration_ms=result.duration_ms,
                error=result.error,
            )

    result = await repeater.send(req.method, req.url, req.headers, req.body)
    return RepeaterResponse(
        status_code=result.status_code,
        headers=result.headers,
        body=result.body[:50000],
        duration_ms=result.duration_ms,
        error=result.error,
    )


@router.delete("/proxy/history/{capture_id}")
async def delete_capture(capture_id: str, user: str = Depends(get_current_user)):
    from bugfinder.database.models import ProxyCapture
    from bugfinder.database.session import async_session

    async with async_session() as session:
        c = await session.get(ProxyCapture, capture_id)
        if c:
            await session.delete(c)
            await session.commit()
            return {"success": True}
        raise HTTPException(status_code=404, detail="Capture not found")


@router.delete("/proxy/history")
async def clear_history(user: str = Depends(get_current_user)):
    from sqlalchemy import delete

    from bugfinder.database.models import ProxyCapture
    from bugfinder.database.session import async_session

    async with async_session() as session:
        await session.execute(delete(ProxyCapture))
        await session.commit()
        return {"success": True}
