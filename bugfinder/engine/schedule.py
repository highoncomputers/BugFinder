from __future__ import annotations

import logging
from collections.abc import Callable, Coroutine
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()


class ScheduledScan:
    def __init__(
        self,
        scan_id: int,
        target: str,
        profile: str = "quick",
        cron: str | None = None,
        interval_minutes: int | None = None,
        max_instances: int = 1,
    ):
        self.scan_id = scan_id
        self.target = target
        self.profile = profile
        self.cron = cron
        self.interval_minutes = interval_minutes
        self.max_instances = max_instances
        self.job_id = f"scan_{scan_id}"


class ScanScheduler:
    def __init__(self):
        self._scheduled: dict[int, ScheduledScan] = {}

    def start(self):
        if not scheduler.running:
            scheduler.start()
            logger.info("Scan scheduler started")

    def stop(self):
        if scheduler.running:
            scheduler.shutdown(wait=False)
            logger.info("Scan scheduler stopped")

    def add_cron_scan(
        self,
        scan_id: int,
        target: str,
        cron: str,
        profile: str = "quick",
        run_func: Callable[..., Coroutine[Any, Any, Any]] | None = None,
    ) -> ScheduledScan:
        ss = ScheduledScan(scan_id=scan_id, target=target, profile=profile, cron=cron)

        trigger = CronTrigger.from_crontab(cron)

        async def run():
            if run_func:
                await run_func(target, profile)

        scheduler.add_job(
            run,
            trigger=trigger,
            id=ss.job_id,
            replace_existing=True,
            max_instances=ss.max_instances,
        )

        self._scheduled[scan_id] = ss
        logger.info("Scheduled cron scan %d: %s (%s)", scan_id, target, cron)
        return ss

    def add_interval_scan(
        self,
        scan_id: int,
        target: str,
        interval_minutes: int,
        profile: str = "quick",
        run_func: Callable[..., Coroutine[Any, Any, Any]] | None = None,
    ) -> ScheduledScan:
        ss = ScheduledScan(scan_id=scan_id, target=target, profile=profile, interval_minutes=interval_minutes)

        trigger = IntervalTrigger(minutes=interval_minutes)

        async def run():
            if run_func:
                await run_func(target, profile)

        scheduler.add_job(
            run,
            trigger=trigger,
            id=ss.job_id,
            replace_existing=True,
            max_instances=ss.max_instances,
        )

        self._scheduled[scan_id] = ss
        logger.info("Scheduled interval scan %d: %s (every %d min)", scan_id, target, interval_minutes)
        return ss

    def remove_scan(self, scan_id: int) -> bool:
        ss = self._scheduled.pop(scan_id, None)
        if ss and scheduler.get_job(ss.job_id):
            scheduler.remove_job(ss.job_id)
            logger.info("Removed scheduled scan %d", scan_id)
            return True
        return False

    def list_scheduled(self) -> list[ScheduledScan]:
        return list(self._scheduled.values())
