from __future__ import annotations

import logging

from bugfinder.agents.base import AgentResult, BaseAgent

logger = logging.getLogger(__name__)


class VerificationAgent(BaseAgent):
    name = "verification"
    description = "Verify findings by retesting with exploit engine"

    async def execute(self) -> AgentResult:
        findings = self.context.knowledge_graph.get_nodes_by_type("finding")
        target_str = str(getattr(self.context.target, "raw", "") or getattr(self.context.target, "url", "") or "")

        verified = 0
        false_positives = 0
        not_verifiable = 0
        details: list[str] = []

        from bugfinder.engine.poc_generator import PoCGenerator
        from bugfinder.exploit.executor import ExploitExecutor

        executor = ExploitExecutor(timeout=10, dry_run=True)

        for node_id, node_data in findings:
            title = node_data.get("title", "Untitled")
            category = node_data.get("category", "")

            try:
                finding = _FindingProxy(title, category, node_data.get("severity", "info"))
                poc = PoCGenerator.generate_poc(finding, target_str)
                if poc:
                    result = await executor.verify_finding(finding, target_str)
                    if result.success and "DRY RUN" not in result.output:
                        verified += 1
                        details.append(f"✓ {title[:50]}: verified")
                    else:
                        if result.error:
                            not_verifiable += 1
                            details.append(f"? {title[:50]}: {result.error}")
                        else:
                            false_positives += 1
                            details.append(f"✗ {title[:50]}: false positive (no confirmation)")
                else:
                    not_verifiable += 1
                    details.append(f"- {title[:50]}: no PoC available, manual check needed")
            except Exception as e:
                logger.warning(f"Verification failed for {node_id}: {e}")
                not_verifiable += 1
                details.append(f"! {title[:50]}: error during verification")

        summary_parts = []
        if verified:
            summary_parts.append(f"{verified} verified")
        if false_positives:
            summary_parts.append(f"{false_positives} likely false positives")
        if not_verifiable:
            summary_parts.append(f"{not_verifiable} not verifiable (manual check)")
        summary = f"Verification: {', '.join(summary_parts) if summary_parts else 'no findings to verify'}"

        return AgentResult(
            agent_name=self.name,
            status="completed",
            summary=summary,
        )


class _FindingProxy:
    def __init__(self, title: str, category: str, severity: str):
        self.title = title
        self.category = category
        self.severity = severity
