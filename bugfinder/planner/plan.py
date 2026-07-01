from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PlanStep:
    agent_name: str
    priority: int = 0
    depends_on: list[str] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)
    rationale: str = ""
    completed: bool = False
    skipped: bool = False


@dataclass
class AssessmentPlan:
    target: str
    target_type: str
    steps: list[PlanStep] = field(default_factory=list)
    current_step_index: int = 0

    @property
    def total_steps(self) -> int:
        return len(self.steps)

    @property
    def completed_steps(self) -> int:
        return sum(1 for s in self.steps if s.completed or s.skipped)

    @property
    def progress(self) -> float:
        if not self.steps:
            return 0.0
        return self.completed_steps / len(self.steps)

    @property
    def current_step(self) -> PlanStep | None:
        if 0 <= self.current_step_index < len(self.steps):
            return self.steps[self.current_step_index]
        return None

    def add_step(self, step: PlanStep) -> None:
        self.steps.append(step)

    def next_step(self) -> PlanStep | None:
        if self.current_step_index < len(self.steps) - 1:
            self.current_step_index += 1
        return self.current_step

    def mark_current_complete(self) -> None:
        if self.current_step:
            self.current_step.completed = True
