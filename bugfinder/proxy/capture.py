from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


class ProxyCaptureStore:
    def __init__(self):
        self._buffer: list[dict[str, Any]] = []
        self._max_buffer = 100

    async def save(self, data: dict[str, Any]) -> str | None:
        self._buffer.append(data)
        if len(self._buffer) >= self._max_buffer:
            await self.flush()
        return data.get("id")

    async def flush(self) -> None:
        if not self._buffer:
            return
        items = self._buffer.copy()
        self._buffer.clear()

        from bugfinder.database.repository import Repository
        from bugfinder.database.session import async_session
        from bugfinder.database.models import ProxyCapture

        try:
            async with async_session() as session:
                repo = Repository(session)
                for item in items:
                    pc = ProxyCapture(
                        id=item.get("id", ""),
                        method=item.get("method", "GET"),
                        host=item.get("host", ""),
                        port=item.get("port", 80),
                        path=item.get("path", "/"),
                        request_headers=item.get("request_headers", ""),
                        request_body=item.get("request_body", ""),
                        status_code=item.get("status_code"),
                        response_headers=item.get("response_headers", ""),
                        response_body=item.get("response_body", ""),
                        content_type=item.get("content_type"),
                        duration_ms=item.get("duration_ms"),
                        size_bytes=item.get("size_bytes"),
                        remote_addr=item.get("remote_addr"),
                        created_at=datetime.now(UTC),
                        tags=item.get("tags"),
                    )
                    session.add(pc)
                await session.commit()
        except Exception as e:
            logger.warning(f"Proxy capture flush error: {e}")

    async def get_history(self, limit: int = 100, offset: int = 0,
                          host: str | None = None) -> list[dict[str, Any]]:
        from bugfinder.database.repository import Repository
        from bugfinder.database.session import async_session
        from sqlalchemy import select, desc

        async with async_session() as session:
            stmt = select(ProxyCapture).order_by(desc(ProxyCapture.created_at))
            if host:
                stmt = stmt.where(ProxyCapture.host == host)
            stmt = stmt.offset(offset).limit(limit)
            result = await session.execute(stmt)
            captures = result.scalars().all()
            return [
                {
                    "id": c.id,
                    "method": c.method,
                    "host": c.host,
                    "port": c.port,
                    "path": c.path,
                    "status_code": c.status_code,
                    "content_type": c.content_type,
                    "duration_ms": c.duration_ms,
                    "size_bytes": c.size_bytes,
                    "remote_addr": c.remote_addr,
                    "created_at": c.created_at.isoformat() if c.created_at else "",
                    "tags": c.tags,
                }
                for c in captures
            ]

    async def get_detail(self, capture_id: str) -> dict[str, Any] | None:
        from bugfinder.database.repository import Repository
        from bugfinder.database.session import async_session

        async with async_session() as session:
            repo = Repository(session)
            from bugfinder.database.models import ProxyCapture
            c = await session.get(ProxyCapture, capture_id)
            if not c:
                return None
            return {
                "id": c.id,
                "method": c.method,
                "host": c.host,
                "port": c.port,
                "path": c.path,
                "request_headers": c.request_headers or "",
                "request_body": c.request_body or "",
                "status_code": c.status_code,
                "response_headers": c.response_headers or "",
                "response_body": c.response_body or "",
                "content_type": c.content_type or "",
                "duration_ms": c.duration_ms,
                "size_bytes": c.size_bytes,
                "remote_addr": c.remote_addr,
                "created_at": c.created_at.isoformat() if c.created_at else "",
                "tags": c.tags or "",
            }
