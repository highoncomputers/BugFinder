from __future__ import annotations

from fastapi import APIRouter, Depends

from bugfinder.web.auth import get_current_user
from bugfinder.web.models import AgentResponse

router = APIRouter()


@router.get("", response_model=list[AgentResponse])
async def list_agents(user: str = Depends(get_current_user)):
    from bugfinder.core.registry import registry

    registry.discover_agents()
    agents = registry._agents
    result = []
    for name, cls in agents.items():
        category = getattr(cls, "category", "unknown")
        result.append(
            AgentResponse(
                name=name,
                category=category,
                description=cls.__doc__ or "",
                enabled=True,
            )
        )
    return result
