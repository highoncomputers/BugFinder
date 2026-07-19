from __future__ import annotations

from collections.abc import AsyncGenerator
from functools import lru_cache
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from bugfinder.core.config import settings
from bugfinder.database.models import Base


@lru_cache(maxsize=1)
def get_engine():
    url = settings.database_url
    if not url:
        raise RuntimeError("BF_DATABASE_URL is not set. Configure it in .env or set the environment variable.")
    return create_async_engine(url, echo=settings.debug)


@lru_cache(maxsize=1)
def get_session_factory():
    engine = get_engine()
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class _AsyncSessionProxy:
    def __call__(self) -> AsyncSession:
        return get_session_factory()()

    def __getattr__(self, name: str) -> Any:
        return getattr(get_session_factory(), name)


# Backward-compatible lazy proxy — replaces old `async_session` module-level factory
async_session = _AsyncSessionProxy()


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        yield session


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        yield session


async def init_db() -> None:
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    engine = get_engine()
    await engine.dispose()
    get_engine.cache_clear()
    get_session_factory.cache_clear()


def get_sync_engine_url() -> str:
    url = settings.database_url
    if not url:
        return "sqlite:///bugfinder.db"
    if url.startswith("sqlite+aiosqlite"):
        url = "sqlite:///" + url.removeprefix("sqlite+aiosqlite:///")
    return url
