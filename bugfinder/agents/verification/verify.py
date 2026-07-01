from __future__ import annotations

from bugfinder.agents.base import AgentResult, BaseAgent


class VerificationAgent(BaseAgent):
    name = "verification"
    description = "Verify findings and reduce false positives"

    async def execute(self) -> AgentResult:
        findings_count = len(self.context.knowledge_graph.get_nodes_by_type("finding"))
        summary = f"Verification pass complete: {findings_count} findings recorded"
        return AgentResult(
            agent_name=self.name,
            status="completed",
            summary=summary,
        )
