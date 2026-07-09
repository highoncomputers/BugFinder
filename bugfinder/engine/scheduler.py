from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from bugfinder.agents.base import AgentContext, AgentResult
from bugfinder.ai.client import get_ai_client
from bugfinder.core.config import settings
from bugfinder.core.types import TargetType
from bugfinder.database.repository import Repository
from bugfinder.database.session import async_session
from bugfinder.knowledge_graph.graph import KnowledgeGraph
from bugfinder.planner.ai_planner import AIPlanner
from bugfinder.planner.plan import AssessmentPlan
from bugfinder.planner.rule_planner import RulePlanner
from bugfinder.web.routes.sse import update_scan_progress


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
        knowledge_graph: KnowledgeGraph | None = None,
        ai_client: Any | None = None,
        repository: Repository | None = None,
    ) -> None:
        self.kg = knowledge_graph or KnowledgeGraph()
        self.ai_client = ai_client or get_ai_client()
        self.repo = repository
        self.progress = ScanProgress(target="", target_type="")
        self._start_time: float = 0.0

    def log(self, message: str) -> None:
        self.progress.log.append(message)

    def _build_agent_context(self, target: str, target_type: str, scan_id: int) -> AgentContext:
        from bugfinder.target.parsers import parse_target
        parsed = parse_target(target)
        return AgentContext(
            target=parsed,
            target_type=target_type,
            knowledge_graph=self.kg,
            ai_client=self.ai_client,
            repository=self.repo,
        )

    async def _load_agent(self, agent_name: str) -> Any:
        from bugfinder.agents.android.decompile import DecompileAgent
        from bugfinder.agents.android.deeplinks import DeepLinkAgent
        from bugfinder.agents.android.storage import AndroidStorageAgent
        from bugfinder.agents.android.webview import AndroidWebViewAgent
        from bugfinder.agents.api.discover import APIDiscoverAgent
        from bugfinder.agents.api.fuzz import APIFuzzAgent
        from bugfinder.agents.api.rate import APIRateAgent
        from bugfinder.agents.cloud.azure import AzureAgent
        from bugfinder.agents.cloud.detect import CloudAgent
        from bugfinder.agents.cloud.firebase import FirebaseAgent
        from bugfinder.agents.cloud.gcp import GCPAgent
        from bugfinder.agents.cloud.s3 import S3Agent
        from bugfinder.agents.correlation import CorrelationAgent
        from bugfinder.agents.infra.port import PortScanAgent
        from bugfinder.agents.infra.service import ServiceDetectAgent
        from bugfinder.agents.infra.tls import TLSScanAgent
        from bugfinder.agents.recon.dns import DNSAgent
        from bugfinder.agents.recon.github import GitHubAgent
        from bugfinder.agents.recon.googledorks import GoogleDorkAgent
        from bugfinder.agents.recon.tech import TechDetectAgent
        from bugfinder.agents.recon.wayback import WaybackAgent
        from bugfinder.agents.secrets.scan import SecretsScanAgent
        from bugfinder.agents.verification.verify import VerificationAgent
        from bugfinder.agents.web.auth import AuthAgent
        from bugfinder.agents.web.cache import CachePoisonAgent
        from bugfinder.agents.web.cookies import CookieSecurityAgent
        from bugfinder.agents.web.cors import CORSAgent
        from bugfinder.agents.web.crawler import CrawlerAgent
        from bugfinder.agents.web.csp import CSPAgent
        from bugfinder.agents.web.csrf import CSRFAgent
        from bugfinder.agents.web.graphql import GraphQLAgent
        from bugfinder.agents.web.host_header import HostHeaderAgent
        from bugfinder.agents.web.js import JSAnalyzerAgent
        from bugfinder.agents.web.jwt import JWTAgent
        from bugfinder.agents.web.lfi import LFIAgent
        from bugfinder.agents.web.race import RaceConditionAgent
        from bugfinder.agents.web.redirect import OpenRedirectAgent
        from bugfinder.agents.web.sqli import SQLiAgent
        from bugfinder.agents.web.ssrf import SSRFAgent
        from bugfinder.agents.web.ssti import SSTIAgent
        from bugfinder.agents.web.xss import XSSAgent
        from bugfinder.agents.web.xxe import XXEAgent

        agent_map: dict[str, type] = {
            "recon.dns": DNSAgent,
            "recon.tech": TechDetectAgent,
            "recon.wayback": WaybackAgent,
            "recon.github": GitHubAgent,
            "recon.googledorks": GoogleDorkAgent,
            "web.crawler": CrawlerAgent,
            "web.js": JSAnalyzerAgent,
            "web.auth": AuthAgent,
            "web.xss": XSSAgent,
            "web.sqli": SQLiAgent,
            "web.ssrf": SSRFAgent,
            "web.lfi": LFIAgent,
            "web.ssti": SSTIAgent,
            "web.xxe": XXEAgent,
            "web.graphql": GraphQLAgent,
            "web.jwt": JWTAgent,
            "web.cors": CORSAgent,
            "web.cookies": CookieSecurityAgent,
            "web.csrf": CSRFAgent,
            "web.csp": CSPAgent,
            "web.redirect": OpenRedirectAgent,
            "web.host_header": HostHeaderAgent,
            "web.race": RaceConditionAgent,
            "web.cache": CachePoisonAgent,
            "api.discover": APIDiscoverAgent,
            "api.fuzz": APIFuzzAgent,
            "api.rate": APIRateAgent,
            "secrets.scan": SecretsScanAgent,
            "correlation": CorrelationAgent,
            "verification": VerificationAgent,
            "infra.port": PortScanAgent,
            "infra.service": ServiceDetectAgent,
            "infra.tls": TLSScanAgent,
            "cloud.detect": CloudAgent,
            "cloud.s3": S3Agent,
            "cloud.gcp": GCPAgent,
            "cloud.azure": AzureAgent,
            "cloud.firebase": FirebaseAgent,
            "android.decompile": DecompileAgent,
            "android.webview": AndroidWebViewAgent,
            "android.storage": AndroidStorageAgent,
            "android.deeplinks": DeepLinkAgent,
        }

        cls = agent_map.get(agent_name)
        if cls:
            return cls()

        from bugfinder.agents.base import BaseAgent

        class StubAgent(BaseAgent):
            name = agent_name
            description = f"Stub for {agent_name}"

            async def execute(self, context: AgentContext) -> AgentResult:
                return AgentResult(
                    agent_name=agent_name,
                    status="completed",
                    summary=f"Stub: {agent_name} (not yet implemented)",
                )

        return StubAgent()

    async def run_scan(self, scan_id: int, target: str, target_type: TargetType, profile: str = "auto") -> AssessmentPlan:
        self._start_time = time.monotonic()
        ttype_str = target_type.value if hasattr(target_type, "value") else str(target_type)
        self.progress = ScanProgress(target=target, target_type=ttype_str)
        self.progress.status = "running"

        update_scan_progress(scan_id, {"status": "running", "progress": 0, "target": target})

        if self.ai_client and settings.ai_enabled:
            planner = AIPlanner(self.kg, self.ai_client, self.repo)
        else:
            planner = RulePlanner(self.kg, self.repo)

        plan = await planner.create_plan(target, ttype_str)
        self.progress.total_steps = plan.total_steps

        ctx = self._build_agent_context(target, ttype_str, scan_id)

        for i, step in enumerate(plan.steps):
            elapsed = time.monotonic() - self._start_time
            self.progress.current_step = step.agent_name
            self.progress.current_rationale = step.rationale
            self.progress.elapsed_seconds = elapsed
            self.progress.percent = (i / max(plan.total_steps, 1)) * 100
            self.log(f"Step {i + 1}/{plan.total_steps}: {step.rationale}")

            update_scan_progress(scan_id, {
                "step": step.agent_name,
                "progress": self.progress.percent,
                "rationale": step.rationale,
            })

            agent = await self._load_agent(step.agent_name)
            try:
                result = await agent.execute(ctx)
                if result and result.findings:
                    self.progress.findings_count += len(result.findings)
                    for f_data in result.findings:
                        self.kg.add_node(
                            f_data.get("id", f"finding-{id(f_data)}"),
                            "finding",
                            **f_data,
                        )
                    await self._persist_findings(scan_id, result.findings)
                if result and result.assets:
                    for a_data in result.assets:
                        self.kg.add_node(
                            a_data.get("id", f"asset-{id(a_data)}"),
                            "asset",
                            **a_data,
                        )

                step.completed = True
                self.progress.completed_steps += 1
                summary = result.summary if result else "Completed"
                self.log(f"  ✓ {step.agent_name}: {summary}")
            except Exception as e:
                step.skipped = True
                self.log(f"  ✗ {step.agent_name}: {e}")

        self.progress.status = "completed"
        self.progress.percent = 100.0
        self.log("Scan complete")

        update_scan_progress(scan_id, {"status": "completed", "progress": 100, "findings": self.progress.findings_count})

        async with async_session() as session:
            repo = Repository(session)
            await repo.update_scan(
                scan_id,
                status="completed",
                progress=100.0,
            )

        return plan

    async def stop_scan(self, scan_id: int) -> bool:
        self.progress.status = "cancelled"
        update_scan_progress(scan_id, {"status": "cancelled"})
        return True

    async def _persist_findings(self, scan_id: int, findings: list[dict]) -> None:
        async with async_session() as session:
            repo = Repository(session)
            for f in findings:
                await repo.create_finding(
                    scan_id=scan_id,
                    title=f.get("title", "Untitled"),
                    description=f.get("description", ""),
                    severity=f.get("severity", "medium"),
                    confidence=f.get("confidence", "medium"),
                    category=f.get("category"),
                    evidence=f.get("evidence"),
                    cwe_id=f.get("cwe_id"),
                    owasp_category=f.get("owasp_category"),
                    cvss_score=f.get("cvss_score"),
                    remediation=f.get("remediation"),
                )
