from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from bugfinder.web.auth import get_current_user

router = APIRouter()


class RemediationResponse:
    pass


@router.get("/remediation/{finding_id}")
async def get_remediation(finding_id: str, user: str = Depends(get_current_user)):
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session
    from bugfinder.reporting.auto_fix import generate_fixes_for_finding

    async with async_session() as session:
        repo = Repository(session)
        finding = await repo.get_finding(finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        fixes = generate_fixes_for_finding(finding)

        return {
            "finding_id": finding_id,
            "finding_title": finding.title or "",
            "fixes": fixes,
            "existing_remediation": finding.remediation or "",
        }
