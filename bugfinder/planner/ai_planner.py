from __future__ import annotations

from bugfinder.ai.client import BaseAIProvider
from bugfinder.database.repository import Repository
from bugfinder.knowledge_graph.graph import KnowledgeGraph
from bugfinder.planner.base import BasePlanner
from bugfinder.planner.plan import AssessmentPlan, PlanStep

PLANNER_SYSTEM_PROMPT = """You are BugFinder's AI security assessment planner.
Your role is to analyze the target, review current findings, and decide the next best step.
Only recommend steps that are legal and within scope.
Be concise and specific. Output JSON with:
{{"step": "...", "rationale": "...", "agent": "...", "config": {{}}}}"""


class AIPlanner(BasePlanner):
    def __init__(
        self,
        knowledge_graph: KnowledgeGraph,
        ai_client: BaseAIProvider | None = None,
        repository: Repository | None = None,
    ) -> None:
        super().__init__(knowledge_graph, ai_client, repository)
        self._plan: AssessmentPlan | None = None

    async def create_plan(self, target: str, target_type: str) -> AssessmentPlan:
        plan = AssessmentPlan(target=target, target_type=target_type)
        if not self.ai_client:
            from bugfinder.planner.rule_planner import RulePlanner

            fallback = RulePlanner(self.knowledge_graph)
            return await fallback.create_plan(target, target_type)

        try:
            prompt = (
                f"Target: {target}\n"
                f"Target Type: {target_type}\n"
                f"Current Knowledge: {self.knowledge_graph.node_count} assets discovered\n\n"
                "Generate an assessment plan. Return a JSON array of steps, "
                "each with 'agent' (name), 'rationale' (why), and 'priority' (0-100)."
            )
            result = await self.ai_client.chat_json(
                system_prompt=PLANNER_SYSTEM_PROMPT,
                user_prompt=prompt,
            )
            steps = result if isinstance(result, list) else result.get("steps", [])
            for i, step_data in enumerate(steps):
                step = PlanStep(
                    agent_name=step_data.get("agent", "unknown"),
                    priority=step_data.get("priority", i),
                    rationale=step_data.get("rationale", ""),
                    config=step_data.get("config", {}),
                )
                plan.add_step(step)
        except Exception:
            from bugfinder.planner.rule_planner import RulePlanner

            fallback = RulePlanner(self.knowledge_graph)
            plan = await fallback.create_plan(target, target_type)

        return plan

    async def revise_plan(self, completed_agent: str, result_summary: str) -> AssessmentPlan | None:
        if not self._plan or not self.ai_client:
            return None

        prompt = (
            f"Completed agent: {completed_agent}\n"
            f"Result: {result_summary}\n"
            f"Remaining steps: {[s.agent_name for s in self._plan.steps if not s.completed]}\n\n"
            "Should we continue, skip any steps, or add new ones? "
            'Respond with JSON: {"action": "continue|skip|add", "agent": "...", "rationale": "..."}'
        )
        try:
            result = await self.ai_client.chat_json(
                system_prompt=PLANNER_SYSTEM_PROMPT,
                user_prompt=prompt,
            )
            action = result.get("action", "continue")
            if action == "skip":
                for step in self._plan.steps:
                    if not step.completed and step.agent_name == result.get("agent"):
                        step.skipped = True
            elif action == "add" and result.get("agent"):
                step = PlanStep(
                    agent_name=result["agent"],
                    priority=self._plan.total_steps,
                    rationale=result.get("rationale", ""),
                )
                self._plan.add_step(step)
        except Exception:
            pass

        return self._plan
