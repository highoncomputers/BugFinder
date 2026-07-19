from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from typing import Any

from bugfinder.core.config import Settings

logger = logging.getLogger(__name__)


class ParallelOrchestrator:
    def __init__(self, max_concurrent: int | None = None):
        settings = Settings()
        self.max_concurrent = max_concurrent or settings.max_concurrent_tasks
        self._semaphore: asyncio.Semaphore | None = None

    async def run_batch(
        self,
        tasks: list[Callable[..., Coroutine[Any, Any, Any]]],
        task_args: list[tuple] | None = None,
        raise_on_error: bool = False,
    ) -> list[Any]:
        sem = asyncio.Semaphore(self.max_concurrent)

        async def _run(task_idx: int) -> Any:
            async with sem:
                try:
                    fn = tasks[task_idx]
                    args = task_args[task_idx] if task_args else ()
                    return await fn(*args)
                except Exception as e:
                    logger.error("Task %d failed: %s", task_idx, e)
                    if raise_on_error:
                        raise
                    return None

        results = await asyncio.gather(
            *[_run(i) for i in range(len(tasks))],
            return_exceptions=not raise_on_error,
        )
        return [r for r in results if r is not None and not isinstance(r, Exception)]

    async def run_agent_batch(
        self,
        agents: list[Any],
        context: Any,
    ) -> list[Any]:
        from bugfinder.agents.base import BaseAgent

        sem = asyncio.Semaphore(self.max_concurrent)

        async def _run_agent(agent: BaseAgent) -> Any:
            async with sem:
                try:
                    logger.info("Running agent: %s", agent.__class__.__name__)
                    return await agent.execute(context)
                except Exception as e:
                    logger.error("Agent %s failed: %s", agent.__class__.__name__, e)
                    return None

        results = await asyncio.gather(
            *[_run_agent(a) for a in agents],
            return_exceptions=True,
        )
        return [r for r in results if r is not None and not isinstance(r, Exception)]
