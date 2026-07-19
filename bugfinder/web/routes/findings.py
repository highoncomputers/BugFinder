from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from bugfinder.web.auth import get_current_user
from bugfinder.web.models import FindingResponse, FindingUpdate

router = APIRouter()


@router.get("", response_model=list[FindingResponse])
async def list_findings(
    scan_id: str | None = Query(None),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    category: str | None = Query(None),
    user: str = Depends(get_current_user),
):
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session

    async with async_session() as session:
        repo = Repository(session)
        findings = await repo.list_findings(scan_id=scan_id)
        result = []
        for f in findings:
            sev = f.severity if isinstance(f.severity, str) else f.severity.value if hasattr(f.severity, "value") else "medium"
            st = f.status if isinstance(f.status, str) else f.status.value if hasattr(f.status, "value") else "open"
            conf = (
                f.confidence
                if isinstance(f.confidence, str)
                else f.confidence.value
                if hasattr(f.confidence, "value")
                else "medium"
            )
            if severity and sev != severity:
                continue
            if status and st != status:
                continue
            if category and f.category != category:
                continue
            result.append(
                FindingResponse(
                    id=f.id,
                    scan_id=f.scan_id,
                    title=f.title,
                    description=f.description or "",
                    severity=sev,
                    confidence=conf,
                    status=st,
                    category=f.category,
                    cwe_id=f.cwe_id,
                    owasp_category=f.owasp_category,
                    cvss_score=f.cvss_score,
                    evidence=f.evidence,
                    remediation=f.remediation,
                    created_at=f.discovered_at,
                )
            )
        return result


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: str, user: str = Depends(get_current_user)):
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session

    async with async_session() as session:
        repo = Repository(session)
        f = await repo.get_finding(finding_id)
        if not f:
            raise HTTPException(status_code=404, detail="Finding not found")
        return FindingResponse(
            id=f.id,
            scan_id=f.scan_id,
            title=f.title,
            description=f.description or "",
            severity=f.severity if isinstance(f.severity, str) else f.severity.value,
            confidence=f.confidence if isinstance(f.confidence, str) else f.confidence.value,
            status=f.status if isinstance(f.status, str) else f.status.value,
            category=f.category,
            cwe_id=f.cwe_id,
            owasp_category=f.owasp_category,
            cvss_score=f.cvss_score,
            evidence=f.evidence,
            remediation=f.remediation,
            created_at=f.discovered_at,
        )


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(finding_id: str, data: FindingUpdate, user: str = Depends(get_current_user)):
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session

    async with async_session() as session:
        repo = Repository(session)
        f = await repo.get_finding(finding_id)
        if not f:
            raise HTTPException(status_code=404, detail="Finding not found")

        if data.status:
            await repo.update_finding_status(finding_id, data.status)

        f = await repo.get_finding(finding_id)
        return FindingResponse(
            id=f.id,
            scan_id=f.scan_id,
            title=f.title,
            description=f.description or "",
            severity=f.severity if isinstance(f.severity, str) else f.severity.value,
            confidence=f.confidence if isinstance(f.confidence, str) else f.confidence.value,
            status=f.status if isinstance(f.status, str) else f.status.value,
            category=f.category,
            cwe_id=f.cwe_id,
            owasp_category=f.owasp_category,
            cvss_score=f.cvss_score,
            evidence=f.evidence,
            remediation=f.remediation,
            created_at=f.discovered_at,
        )
