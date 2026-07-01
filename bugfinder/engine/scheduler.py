from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from bugfinder.agents.base import AgentContext, AgentResult
from bugfinder.ai.client import NVIDIAClient
from bugfinder.core.config import settings
from bugfinder.database.repository import Repository
from bugfinder.knowledge_graph.graph import KnowledgeGraph
from bugfinder.planner.ai_planner import AIPlanner
from bugfinder.planner.plan import AssessmentPlan
from bugfinder.planner.rule_planner import RulePlanner


@dataclass
class ScanProgress:
    target: str
    target_type: str
    total_steps: int = 0
    completed_steps: int = 0
    current_step: str = ""
    current_rationale: str = ""
    findings_count: int = 0
    status: str = "pending"
    percent: float = 0.0
    elapsed_seconds: float = 0.0
    estimated_remaining: str = ""
    log: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "status": self.status,
            "progress": self.percent,
            "step": self.current_step,
            "findings": self.findings_count,
            "elapsed": self.elapsed_seconds,
        }


class ScanOrchestrator:
    def __init__(
        self,
        knowledge_graph: KnowledgeGraph,
        ai_client: NVIDIAClient | None = None,
        repository: Repository | None = None,
    ) -> None:
        self.kg = knowledge_graph
        self.ai_client = ai_client
        self.repo = repository
        self.progress = ScanProgress(target="", target_type="")
        self._start_time: float = 0.0
        self._agent_instances: dict[str, Any] = {}

    def log(self, message: str) -> None:
        self.progress.log.append(message)

    def _build_agent_context(self, target: str, target_type: str, scan_id: str) -> AgentContext:
        return AgentContext(
            target=target,
            target_type=target_type,
            scan_id=scan_id,
            knowledge_graph=self.kg,
            ai_client=self.ai_client,
            repository=self.repo,
        )

    async def _load_agent(self, agent_name: str, ctx: AgentContext) -> Any:
        parts = agent_name.split(".")
        module_path = f"bugfinder.agents.{parts[0]}"

        class_name_map = {
            "recon.dns": "DNSAgent",
            "recon.tech": "TechDetectAgent",
            "recon.whois": "WHOISAgent",
            "recon.cert": "CertAgent",
            "web.crawler": "CrawlerAgent",
            "web.js": "JSAnalyzerAgent",
            "web.auth": "AuthAgent",
            "web.xss": "XSSAgent",
            "web.sqli": "SQLiAgent",
            "web.ssrf": "SSRFAgent",
            "web.lfi": "LFIAgent",
            "api.discover": "APIDiscoverAgent",
            "api.auth": "APIAuthAgent",
            "api.fuzz": "APIFuzzAgent",
            "api.rate": "APIRateAgent",
            "secrets.scan": "SecretsScanAgent",
            "verification": "VerificationAgent",
            "infra.port": "PortScanAgent",
            "infra.service": "ServiceDetectAgent",
            "android.decompile": "DecompileAgent",
            "android.manifest": "ManifestAgent",
            "android.web": "AndroidWebAgent",
        }

        class_name = class_name_map.get(agent_name, f"{parts[-1].title()}Agent")

        try:
            mod = __import__(module_path, fromlist=[class_name])
            agent_cls = getattr(mod, class_name)
            instance = agent_cls(ctx)
            return instance
        except (ImportError, AttributeError):
            from bugfinder.agents.base import BaseAgent

            class StubAgent(BaseAgent):
                name = agent_name
                description = f"Stub for {agent_name}"

                async def execute(self) -> AgentResult:
                    return AgentResult(
                        agent_name=agent_name,
                        status="completed",
                        summary=f"Stub: {agent_name} executed (not implemented yet)",
                    )

            return StubAgent(ctx)

    async def run_scan(self, target: str, target_type: str, scan_id: str, profile: str = "auto") -> AssessmentPlan:
        self._start_time = time.monotonic()
        self.progress = ScanProgress(target=target, target_type=target_type)
        self.progress.status = "running"

        if self.ai_client and settings.ai_enabled:
            planner = AIPlanner(self.kg, self.ai_client, self.repo)
        else:
            planner = RulePlanner(self.kg, self.repo)

        plan = await planner.create_plan(target, target_type)
        self.progress.total_steps = plan.total_steps
        self.progress.status = "running"

        ctx = self._build_agent_context(target, target_type, scan_id)

        for i, step in enumerate(plan.steps):
            elapsed = time.monotonic() - self._start_time
            self.progress.current_step = step.agent_name
            self.progress.current_rationale = step.rationale
            self.progress.elapsed_seconds = elapsed
            self.progress.percent = (i / max(plan.total_steps, 1)) * 100
            self.log(f"Step {i + 1}/{plan.total_steps}: {step.rationale}")

            agent = await self._load_agent(step.agent_name, ctx)
            try:
                result = await agent.execute()
                if result.findings:
                    self.progress.findings_count += len(result.findings)
                    for f_data in result.findings:
                        self.kg.add_node(
                            f_data.get("id", f"finding-{len(result.findings)}"),
                            "finding",
                            **f_data,
                        )
                    await self._persist_findings(scan_id, result.findings)
                if result.assets:
                    for a_data in result.assets:
                        self.kg.add_node(
                            a_data.get("id", f"asset-{len(result.assets)}"),
                            "asset",
                            **a_data,
                        )

                step.completed = True
                self.progress.completed_steps += 1
                self.log(f"  ✓ {step.agent_name}: {result.summary}")
            except Exception as e:
                step.skipped = True
                self.log(f"  ✗ {step.agent_name}: {e}")

        self.progress.status = "completed"
        self.progress.percent = 100.0
        self.log("Scan complete")

        return plan

    async def _persist_findings(self, scan_id: str, findings: list[dict]) -> None:
        if not self.repo:
            return
        for f in findings:
            await self.repo.create_finding(
                scan_id=scan_id,
                title=f.get("title", "Untitled"),
                description=f.get("description", ""),
                severity=f.get("severity", "medium"),
                confidence=f.get("confidence", "needs_review"),
                category=f.get("category"),
                evidence=f.get("evidence"),
            )
