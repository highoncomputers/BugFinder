from __future__ import annotations

from fastapi import APIRouter, Depends
from bugfinder.web.models import DashboardStats, ScanResponse
from bugfinder.web.auth import get_current_user

router = APIRouter()


@router.get("/stats", response_model=DashboardStats)
async def dashboard_stats(user: str = Depends(get_current_user)):
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session

    async with async_session() as session:
        repo = Repository(session)
        projects = await repo.list_projects()
        scans = []
        for p in projects:
            scans.extend(await repo.list_scans(project_id=p.id))

        total_findings = 0
        severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        status_counts: dict[str, int] = {}

        recent_scans: list[ScanResponse] = []
        for s in sorted(scans, key=lambda x: x.created_at, reverse=True)[:10]:
            findings = await repo.list_findings(scan_id=s.id)
            total_findings += len(findings)
            for f in findings:
                sev = f.severity if isinstance(f.severity, str) else f.severity.value if hasattr(f.severity, 'value') else "info"
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            st = s.status if isinstance(s.status, str) else s.status.value if hasattr(s.status, 'value') else "unknown"
            status_counts[st] = status_counts.get(st, 0) + 1

            recent_scans.append(ScanResponse(
                id=s.id, target=s.target,
                target_type=s.target_type if isinstance(s.target_type, str) else s.target_type.value if hasattr(s.target_type, 'value') else str(s.target_type),
                status=st, profile=s.profile or "quick",
                progress=s.progress or 0.0, current_step=s.current_step,
                project_id=s.project_id, created_at=s.created_at,
                updated_at=s.updated_at, findings_count=len(findings),
            ))

        return DashboardStats(
            total_projects=len(projects),
            total_scans=len(scans),
            total_findings=total_findings,
            critical_findings=severity_counts.get("critical", 0),
            high_findings=severity_counts.get("high", 0),
            medium_findings=severity_counts.get("medium", 0),
            low_findings=severity_counts.get("low", 0),
            info_findings=severity_counts.get("info", 0),
            scans_by_status=status_counts,
            recent_scans=recent_scans,
        )
