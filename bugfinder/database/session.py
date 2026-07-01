from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from bugfinder.core.config import settings
from bugfinder.database.models import Base

async_engine = create_async_engine(settings.database_url, echo=settings.debug)
async_session_factory = async_sessionmaker(
    async_engine, class_=AsyncSession, expire_on_commit=False
)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        yield session


async def init_db() -> None:
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    await async_engine.dispose()


def get_sync_engine_url() -> str:
    url = settings.database_url
    if url.startswith("sqlite+aiosqlite"):
        url = url.replace("+aiosqlite", "")
    return url
