from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from typing import Any, Optional

from bugfinder.ai.client import BaseAIProvider
from bugfinder.database.repository import Repository
from bugfinder.knowledge_graph.graph import KnowledgeGraph


@dataclass
class AgentContext:
    target: str
    target_type: str
    scan_id: str
    knowledge_graph: KnowledgeGraph
    ai_client: Optional[BaseAIProvider]
    repository: Repository
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResult:
    agent_name: str
    status: str  # completed, failed, skipped
    findings: list[dict[str, Any]] = field(default_factory=list)
    assets: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    error: str | None = None
    data: dict[str, Any] = field(default_factory=dict)


class BaseAgent(ABC):
    name: str = "base"
    description: str = "Base agent"

    def __init__(self, context: AgentContext) -> None:
        self.context = context

    @abstractmethod
    async def execute(self) -> AgentResult: ...

    async def initialize(self) -> None:
        pass

    async def cleanup(self) -> None:
        pass

    async def __call__(self) -> AgentResult:
        await self.initialize()
        try:
            return await self.execute()
        finally:
            await self.cleanup()
