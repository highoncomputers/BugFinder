from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from bugfinder.web.auth import get_current_user

router = APIRouter()


class ChatRequest(BaseModel):
    message: str
    scan_id: int | None = None
    finding_id: int | None = None


class ChatResponse(BaseModel):
    reply: str
    context: dict[str, Any] | None = None


@router.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest, user: str = Depends(get_current_user)):
    from bugfinder.ai.chat_agent import ChatAgent
    from bugfinder.ai.client import get_ai_client

    ai_client = get_ai_client()
    agent = ChatAgent(ai_client)
    context = await _build_context(req.scan_id, req.finding_id)
    reply = await agent.chat(req.message, context)
    return ChatResponse(reply=reply, context=context)


@router.post("/chat/clear")
async def clear_chat(user: str = Depends(get_current_user)):
    from bugfinder.ai.chat_agent import ChatAgent

    agent = ChatAgent()
    agent.clear_history()
    return {"success": True}


async def _build_context(scan_id: int | None, finding_id: int | None) -> dict[str, Any]:
    context: dict[str, Any] = {}

    if finding_id is not None:
        from bugfinder.database.repository import Repository
        from bugfinder.database.session import async_session

        async with async_session() as session:
            repo = Repository(session)
            finding = await repo.get_finding(str(finding_id))
            if finding:
                context["findings"] = [_finding_to_dict(finding)]
                if finding.scan_id:
                    scan = await repo.get_scan(finding.scan_id)
                    if scan:
                        context["scan"] = {
                            "id": scan.id,
                            "target": scan.target,
                            "profile": scan.profile,
                            "status": scan.status,
                        }
                        all_findings = await repo.list_findings(scan_id=scan.id)
                        context["findings"] = [_finding_to_dict(f) for f in all_findings]

    elif scan_id is not None:
        from bugfinder.database.repository import Repository
        from bugfinder.database.session import async_session

        async with async_session() as session:
            repo = Repository(session)
            scan = await repo.get_scan(str(scan_id))
            if scan:
                context["scan"] = {
                    "id": scan.id,
                    "target": scan.target,
                    "profile": scan.profile,
                    "status": scan.status,
                    "findings_count": 0,
                }
                findings = await repo.list_findings(scan_id=scan.id)
                context["findings"] = [_finding_to_dict(f) for f in findings]
                context["scan"]["findings_count"] = len(findings)

    return context


def _finding_to_dict(f: Any) -> dict[str, Any]:
    return {
        "id": str(getattr(f, "id", "")),
        "title": getattr(f, "title", ""),
        "description": getattr(f, "description", ""),
        "severity": getattr(f, "severity", "info"),
        "confidence": getattr(f, "confidence", "medium"),
        "category": getattr(f, "category", ""),
        "evidence": getattr(f, "evidence", ""),
        "remediation": getattr(f, "remediation", ""),
        "cwe_id": getattr(f, "cwe_id", ""),
    }
