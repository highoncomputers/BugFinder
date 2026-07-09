from __future__ import annotations

from typing import Any, AsyncGenerator
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from bugfinder.agents.base import AgentContext, AgentResult
from bugfinder.knowledge_graph.graph import KnowledgeGraph
from bugfinder.target.parsers import parse_target


@pytest.fixture
def sample_target():
    return "https://example.com"


@pytest.fixture
def parsed_target(sample_target: str):
    return parse_target(sample_target)


@pytest.fixture
def knowledge_graph():
    return KnowledgeGraph()


@pytest.fixture
def mock_ai_client():
    client = AsyncMock()
    client.chat = AsyncMock(return_value={"choices": [{"message": {"content": "test"}}]})
    client.chat_text = AsyncMock(return_value="test response")
    client.chat_json = AsyncMock(return_value={"result": "test"})
    client.is_available = AsyncMock(return_value=True)
    return client


@pytest.fixture
def agent_context(parsed_target, knowledge_graph, mock_ai_client):
    return AgentContext(
        target=parsed_target,
        target_type="website",
        knowledge_graph=knowledge_graph,
        ai_client=mock_ai_client,
        repository=None,
    )


@pytest.fixture
def mock_http_response():
    def _make(status_code: int = 200, text: str = "", headers: dict | None = None):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        resp.headers = headers or {}
        resp.json = MagicMock(return_value={})
        return resp
    return _make
