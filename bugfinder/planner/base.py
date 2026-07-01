from __future__ import annotations

from abc import ABC, abstractmethod

from bugfinder.knowledge_graph.graph import KnowledgeGraph
from bugfinder.ai.client import NVIDIAClient
from bugfinder.database.repository import Repository


class BasePlanner(ABC):
    def __init__(
        self,
        knowledge_graph: KnowledgeGraph,
        ai_client: NVIDIAClient | None = None,
        repository: Repository | None = None,
    ) -> None:
        self.knowledge_graph = knowledge_graph
        self.ai_client = ai_client
        self.repository = repository

    @abstractmethod
    async def create_plan(self, target: str, target_type: str) -> list[dict]:
        ...
