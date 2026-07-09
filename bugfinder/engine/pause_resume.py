from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from bugfinder.core.types import ScanStatus

logger = logging.getLogger(__name__)


class ScanControlState(str, Enum):
    RUNNING = "running"
    PAUSED = "paused"
    CANCELLED = "cancelled"
    COMPLETED = "completed"


@dataclass
class ScanControl:
    scan_id: int
    state: ScanControlState = ScanControlState.RUNNING
    paused_at: Optional[datetime] = None
    resumed_at: Optional[datetime] = None
    cancelled_at: Optional[datetime] = None
    progress: float = 0.0
    current_step: Optional[str] = None
    _pause_event: asyncio.Event = field(default_factory=asyncio.Event)
    _cancel_event: asyncio.Event = field(default_factory=asyncio.Event)

    def __post_init__(self):
        self._pause_event.set()

    async def check(self):
        if self._cancel_event.is_set():
            raise ScanCancelledError(f"Scan {self.scan_id} was cancelled")
        await self._pause_event.wait()

    def pause(self):
        self.state = ScanControlState.PAUSED
        self.paused_at = datetime.utcnow()
        self._pause_event.clear()
        logger.info("Scan %d paused", self.scan_id)

    def resume(self):
        self.state = ScanControlState.RUNNING
        self.resumed_at = datetime.utcnow()
        self._pause_event.set()
        logger.info("Scan %d resumed", self.scan_id)

    def cancel(self):
        self.state = ScanControlState.CANCELLED
        self.cancelled_at = datetime.utcnow()
        self._cancel_event.set()
        self._pause_event.set()
        logger.info("Scan %d cancelled", self.scan_id)


class ScanCancelledError(Exception):
    pass


class ScanManager:
    def __init__(self):
        self._scans: dict[int, ScanControl] = {}

    def register_scan(self, scan_id: int) -> ScanControl:
        ctrl = ScanControl(scan_id=scan_id)
        self._scans[scan_id] = ctrl
        return ctrl

    def get_control(self, scan_id: int) -> Optional[ScanControl]:
        return self._scans.get(scan_id)

    async def pause_scan(self, scan_id: int) -> bool:
        ctrl = self._scans.get(scan_id)
        if ctrl and ctrl.state == ScanControlState.RUNNING:
            ctrl.pause()
            return True
        return False

    async def resume_scan(self, scan_id: int) -> bool:
        ctrl = self._scans.get(scan_id)
        if ctrl and ctrl.state == ScanControlState.PAUSED:
            ctrl.resume()
            return True
        return False

    async def cancel_scan(self, scan_id: int) -> bool:
        ctrl = self._scans.get(scan_id)
        if ctrl and ctrl.state in (ScanControlState.RUNNING, ScanControlState.PAUSED):
            ctrl.cancel()
            return True
        return False

    def remove_scan(self, scan_id: int):
        self._scans.pop(scan_id, None)
