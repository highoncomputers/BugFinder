from __future__ import annotations

import io
import csv
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse, PlainTextResponse, JSONResponse
from pydantic import BaseModel

from bugfinder.web.auth import get_current_user

router = APIRouter()


@router.get("/exports/scan/{scan_id}/csv")
async def export_csv(scan_id: str, user: str = Depends(get_current_user)):
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session

    async with async_session() as session:
        repo = Repository(session)
        scan = await repo.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        findings = await repo.list_findings(scan_id=scan_id)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Title", "Severity", "Confidence", "Status", "Category", "CWE", "CVSS", "Description", "Remediation", "Discovered"])
    for f in findings:
        writer.writerow([
            f.title,
            f.severity.value if hasattr(f.severity, "value") else f.severity,
            f.confidence.value if hasattr(f.confidence, "value") else f.confidence,
            f.status.value if hasattr(f.status, "value") else f.status,
            f.category or "",
            f.cwe_id or "",
            f.cvss_score or "",
            (f.description or "")[:500],
            (f.remediation or "")[:500],
            f.discovered_at.isoformat() if f.discovered_at else "",
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=bugfinder_scan_{scan_id}.csv"},
    )


@router.get("/exports/project/{project_id}/csv")
async def export_project_csv(project_id: str, user: str = Depends(get_current_user)):
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session

    async with async_session() as session:
        repo = Repository(session)
        scans = await repo.list_scans(project_id=project_id)
        if not scans:
            raise HTTPException(status_code=404, detail="No scans found for this project")

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Scan Target", "Title", "Severity", "Confidence", "Status", "Category", "CWE", "CVSS", "Discovered"])
    for scan in scans:
        async with async_session() as session:
            repo = Repository(session)
            findings = await repo.list_findings(scan_id=scan.id)
            for f in findings:
                writer.writerow([
                    scan.target,
                    f.title,
                    f.severity.value if hasattr(f.severity, "value") else f.severity,
                    f.confidence.value if hasattr(f.confidence, "value") else f.confidence,
                    f.status.value if hasattr(f.status, "value") else f.status,
                    f.category or "",
                    f.cwe_id or "",
                    f.cvss_score or "",
                    f.discovered_at.isoformat() if f.discovered_at else "",
                ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=bugfinder_project_{project_id}.csv"},
    )


class JiraIssue(BaseModel):
    project_key: str
    issue_type: str = "Bug"
    summary: str
    description: str
    priority: str = "Medium"
    labels: list[str] = []


@router.post("/exports/jira")
async def export_to_jira(data: list[JiraIssue], user: str = Depends(get_current_user)):
    from bugfinder.core.config import settings

    if not settings.github_token:
        raise HTTPException(status_code=400, detail="Jira integration requires a GitHub token (for API auth)")

    results = []
    base_url = "https://your-jira-instance.atlassian.net"

    import httpx
    async with httpx.AsyncClient() as client:
        for issue in data:
            try:
                resp = await client.post(
                    f"{base_url}/rest/api/2/issue",
                    json={
                        "fields": {
                            "project": {"key": issue.project_key},
                            "issuetype": {"name": issue.issue_type},
                            "summary": issue.summary,
                            "description": issue.description,
                            "priority": {"name": issue.priority},
                            "labels": issue.labels,
                        }
                    },
                    headers={"Authorization": f"Bearer {settings.github_token}"},
                )
                results.append({
                    "summary": issue.summary,
                    "status": resp.status_code,
                    "response": resp.json() if resp.status_code < 400 else resp.text,
                })
            except Exception as e:
                results.append({"summary": issue.summary, "status": 0, "response": str(e)})

    return {"results": results, "total": len(data), "success": sum(1 for r in results if 200 <= r["status"] < 300)}


class H1Report(BaseModel):
    title: str
    description: str
    severity: str
    endpoint: str = ""
    remediation: str = ""
    references: list[str] = []


@router.post("/exports/hackerone")
async def export_to_hackerone(data: list[H1Report]):
    formatted = []
    for r in data:
        formatted.append({
            "data": {
                "type": "report",
                "attributes": {
                    "title": r.title,
                    "vulnerability_information": _h1_description(r),
                    "severity": r.severity.lower(),
                    "endpoint": r.endpoint,
                }
            }
        })
    return JSONResponse(
        content={"reports": formatted, "count": len(formatted), "format": "hackerone"},
        headers={"Content-Disposition": "attachment; filename=hackerone_reports.json"},
    )


@router.post("/exports/bugcrowd")
async def export_to_bugcrowd(data: list[H1Report]):
    formatted = []
    for r in data:
        formatted.append({
            "title": r.title,
            "vulnerability_description": r.description,
            "severity": r.severity.upper(),
            "remediation": r.remediation,
            "references": r.references,
            "endpoint": r.endpoint,
        })
    return JSONResponse(
        content={"submissions": formatted, "count": len(formatted), "format": "bugcrowd"},
        headers={"Content-Disposition": "attachment; filename=bugcrowd_submissions.json"},
    )


@router.get("/exports/scan/{scan_id}/hackerone")
async def export_scan_hackerone(scan_id: str, user: str = Depends(get_current_user)):
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session

    async with async_session() as session:
        repo = Repository(session)
        scan = await repo.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        findings = await repo.list_findings(scan_id=scan_id)

    reports = []
    for f in findings:
        severity = f.severity.value if hasattr(f.severity, "value") else f.severity
        reports.append({
            "title": f.title,
            "description": f.description or "",
            "severity": severity,
            "remediation": f.remediation or "",
            "references": f.references or [],
        })

    return await export_to_hackerone([H1Report(**r) for r in reports])


@router.get("/exports/scan/{scan_id}/bugcrowd")
async def export_scan_bugcrowd(scan_id: str, user: str = Depends(get_current_user)):
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session

    async with async_session() as session:
        repo = Repository(session)
        scan = await repo.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        findings = await repo.list_findings(scan_id=scan_id)

    reports = []
    for f in findings:
        severity = f.severity.value if hasattr(f.severity, "value") else f.severity
        reports.append({
            "title": f.title,
            "description": f.description or "",
            "severity": severity,
            "remediation": f.remediation or "",
            "references": f.references or [],
        })

    return await export_to_bugcrowd([H1Report(**r) for r in reports])


def _h1_description(r: H1Report) -> str:
    parts = [r.description]
    if r.endpoint:
        parts.append(f"\n\n**Endpoint:** `{r.endpoint}`")
    if r.remediation:
        parts.append(f"\n\n**Remediation:** {r.remediation}")
    if r.references:
        parts.append("\n\n**References:**\n" + "\n".join(f"- {ref}" for ref in r.references))
    return "\n".join(parts)
