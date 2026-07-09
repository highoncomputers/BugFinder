from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from bugfinder.core.types import TargetType
from bugfinder.workflow import Phase, PhaseStatus
from bugfinder.workflow.phases import PhaseDefinitions

logger = logging.getLogger(__name__)


@dataclass
class WorkflowProgress:
    phase: Phase
    status: PhaseStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_steps: int = 0
    completed_steps: int = 0
    current_step: Optional[str] = None
    findings_count: int = 0
    error: Optional[str] = None


@dataclass
class WorkflowResult:
    scan_id: int
    target: str
    target_type: TargetType
    profile: str
    progress: list[WorkflowProgress]
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    total_findings: int = 0


class WorkflowEngine:
    def __init__(self, scan_id: int, target: str, target_type: TargetType, profile: str = "quick"):
        self.scan_id = scan_id
        self.target = target
        self.target_type = target_type
        self.profile = profile
        self.progress: dict[Phase, WorkflowProgress] = {}
        self.result = WorkflowResult(
            scan_id=scan_id, target=target, target_type=target_type, profile=profile
        )
        self.phase_defs = PhaseDefinitions()
        self._cancel_event = asyncio.Event()

    @property
    def current_phase(self) -> Optional[Phase]:
        for phase in Phase:
            wp = self.progress.get(phase)
            if wp and wp.status == PhaseStatus.IN_PROGRESS:
                return phase
        return None

    def cancel(self):
        self._cancel_event.set()

    async def run(self) -> WorkflowResult:
        logger.info("Workflow started: scan=%d target=%s profile=%s", self.scan_id, self.target, self.profile)

        for phase in [Phase.RECON, Phase.VULN_DETECTION, Phase.EXPLOITATION, Phase.REPORTING]:
            if self._cancel_event.is_set():
                break

            wp = WorkflowProgress(phase=phase, status=PhaseStatus.IN_PROGRESS, started_at=datetime.utcnow())
            self.progress[phase] = wp

            agents = self.phase_defs.get_agents_for_phase(phase, self.target_type, self.profile)
            wp.total_steps = len(agents)

            if not agents:
                wp.status = PhaseStatus.SKIPPED
                wp.completed_at = datetime.utcnow()
                continue

            logger.info("Phase %s: %d agents", phase.value, len(agents))

            from bugfinder.engine.scheduler import ScanOrchestrator
            orchestrator = ScanOrchestrator()

            for agent_name in agents:
                if self._cancel_event.is_set():
                    wp.status = PhaseStatus.FAILED
                    break

                wp.current_step = agent_name
                logger.info("Running agent %s in phase %s", agent_name, phase.value)

                try:
                    from bugfinder.core.registry import discover_agents
                    all_agents = discover_agents()

                    from bugfinder.database.session import async_session
                    from bugfinder.database.repository import Repository
                    from bugfinder.target.parsers import parse_target
                    from bugfinder.knowledge_graph.graph import KnowledgeGraph

                    target_obj = parse_target(self.target)
                    kg = KnowledgeGraph()
                    from bugfinder.ai.client import get_ai_client
                    ai_client = get_ai_client()

                    context = type('AgentContext', (), {
                        'target': target_obj,
                        'knowledge_graph': kg,
                        'ai_client': ai_client,
                        'repository': None,
                    })()

                    if agent_name in all_agents:
                        agent_cls = all_agents[agent_name]
                        agent = agent_cls()
                        result = await agent.execute(context)
                        if result and result.findings:
                            wp.findings_count += len(result.findings)
                            self.result.total_findings += len(result.findings)
                except Exception as e:
                    logger.error("Agent %s failed: %s", agent_name, e)

                wp.completed_steps += 1

                from bugfinder.web.routes.sse import update_scan_progress
                progress_pct = min(100, int((wp.completed_steps / max(wp.total_steps, 1)) * 100))
                update_scan_progress(self.scan_id, {
                    "phase": phase.value,
                    "agent": agent_name,
                    "progress": progress_pct,
                    "status": "running",
                })

            wp.status = PhaseStatus.COMPLETED if not self._cancel_event.is_set() else PhaseStatus.FAILED
            wp.completed_at = datetime.utcnow()

        self.result.completed_at = datetime.utcnow()
        self.result.progress = list(self.progress.values())

        from bugfinder.web.routes.sse import update_scan_progress
        update_scan_progress(self.scan_id, {
            "status": "completed",
            "progress": 100,
            "total_findings": self.result.total_findings,
        })

        return self.result
