from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from bugfinder.core.config import Settings
from bugfinder.core.types import ScanStatus, TargetType
from bugfinder.engine.scheduler import ScanOrchestrator
from bugfinder.target.detector import detect_target_type

logger = logging.getLogger(__name__)


@dataclass
class BatchTarget:
    target: str
    profile: str = "quick"
    project_id: Optional[int] = None
    name: Optional[str] = None


@dataclass
class BatchResult:
    total: int = 0
    completed: int = 0
    failed: int = 0
    skipped: int = 0
    results: list[dict[str, Any]] = field(default_factory=list)


class BatchScanner:
    def __init__(self, max_concurrent: int | None = None):
        self.settings = Settings()
        self.max_concurrent = max_concurrent or self.settings.max_concurrent_tasks

    @staticmethod
    def parse_target_file(path: str) -> list[BatchTarget]:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Target file not found: {path}")

        targets: list[BatchTarget] = []

        if p.suffix in (".yaml", ".yml"):
            with open(p) as f:
                data = yaml.safe_load(f)
            for item in data if isinstance(data, list) else data.get("targets", []):
                if isinstance(item, str):
                    targets.append(BatchTarget(target=item))
                else:
                    targets.append(BatchTarget(
                        target=item.get("target", item.get("url", "")),
                        profile=item.get("profile", "quick"),
                        project_id=item.get("project_id"),
                        name=item.get("name"),
                    ))
        else:
            with open(p) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split(",")
                        target = parts[0].strip()
                        profile = parts[1].strip() if len(parts) > 1 else "quick"
                        targets.append(BatchTarget(target=target, profile=profile))

        return targets

    async def run_batch(
        self,
        targets: list[BatchTarget],
        raise_on_error: bool = False,
    ) -> BatchResult:
        result = BatchResult(total=len(targets))
        sem = asyncio.Semaphore(self.max_concurrent)

        async def _scan_one(t: BatchTarget) -> dict[str, Any]:
            async with sem:
                try:
                    target_type: TargetType = detect_target_type(t.target)
                    orchestrator = ScanOrchestrator()

                    from bugfinder.database.repository import Repository
                    from bugfinder.database.session import async_session

                    async with async_session() as session:
                        repo = Repository(session)
                        scan = await repo.create_scan(
                            target=t.target,
                            target_type=target_type,
                            profile=t.profile,
                            project_id=t.project_id,
                        )
                        scan_id = scan.id

                    from bugfinder.web.routes.sse import update_scan_progress
                    update_scan_progress(scan_id, {"status": "running", "progress": 0})

                    await orchestrator.run_scan(scan_id, t.target, target_type, t.profile)

                    update_scan_progress(scan_id, {"status": "completed", "progress": 100})

                    async with async_session() as session:
                        repo = Repository(session)
                        scan = await repo.get_scan(scan_id)
                        findings = await repo.list_findings(scan_id=scan_id) if scan else []

                    result.completed += 1
                    return {
                        "target": t.target,
                        "scan_id": scan_id,
                        "status": "completed",
                        "findings_count": len(findings),
                    }
                except Exception as e:
                    logger.error("Batch scan failed for %s: %s", t.target, e)
                    result.failed += 1
                    if raise_on_error:
                        raise
                    return {"target": t.target, "status": "failed", "error": str(e)}

        coros = [_scan_one(t) for t in targets]
        batch_results = await asyncio.gather(*coros, return_exceptions=not raise_on_error)

        for r in batch_results:
            if isinstance(r, dict):
                result.results.append(r)

        return result

    @staticmethod
    def load_targets_from_file(path: str) -> list[str]:
        p = Path(path)
        if not p.exists():
            return []
        targets = []
        with open(p) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
        return targets
