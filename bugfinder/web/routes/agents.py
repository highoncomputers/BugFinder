from __future__ import annotations

from fastapi import APIRouter, Depends
from bugfinder.web.models import AgentResponse
from bugfinder.web.auth import get_current_user

router = APIRouter()


@router.get("", response_model=list[AgentResponse])
async def list_agents(user: str = Depends(get_current_user)):
    from bugfinder.core.registry import discover_agents

    agents = discover_agents()
    result = []
    for name, cls in agents.items():
        category = "unknown"
        if hasattr(cls, "category"):
            category = cls.category
        result.append(AgentResponse(
            name=name,
            category=category,
            description=cls.__doc__ or "",
            enabled=True,
        ))
    return result
