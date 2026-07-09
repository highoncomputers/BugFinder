from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, Query
from bugfinder.web.models import ScanCreate, ScanResponse
from bugfinder.web.auth import get_current_user

router = APIRouter()


@router.get("", response_model=list[ScanResponse])
async def list_scans(
    project_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    user: str = Depends(get_current_user),
):
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session

    async with async_session() as session:
        repo = Repository(session)
        scans = await repo.list_scans(project_id=project_id)
        result = []
        for s in scans:
            if status and hasattr(s.status, 'value') and s.status.value != status:
                continue
            if status and isinstance(s.status, str) and s.status != status:
                continue
            findings = await repo.list_findings(scan_id=s.id)
            result.append(ScanResponse(
                id=s.id, target=s.target,
                target_type=s.target_type if isinstance(s.target_type, str) else s.target_type.value if hasattr(s.target_type, 'value') else str(s.target_type),
                status=s.status if isinstance(s.status, str) else s.status.value if hasattr(s.status, 'value') else str(s.status),
                profile=s.profile or "quick",
                progress=s.progress or 0.0, current_step=s.current_step,
                project_id=s.project_id, created_at=s.created_at,
                updated_at=getattr(s, 'updated_at', s.created_at),
                findings_count=len(findings),
            ))
        return result


@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(data: ScanCreate, user: str = Depends(get_current_user)):
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session
    from bugfinder.core.types import TargetType
    from bugfinder.target.detector import detect_target_type
    from bugfinder.engine.scheduler import ScanOrchestrator

    async with async_session() as session:
        repo = Repository(session)
        target_type = detect_target_type(data.target)
        scan = await repo.create_scan(
            target=data.target,
            target_type=target_type,
            profile=data.profile,
            project_id=data.project_id,
        )
        scan_id = scan.id

    try:
        orchestrator = ScanOrchestrator()
        await orchestrator.run_scan(scan_id, data.target, target_type, data.profile)
    except Exception as exc:
        async with async_session() as session:
            repo = Repository(session)
            await repo.update_scan(scan_id, status="failed", error=str(exc))
        from bugfinder.web.routes.sse import update_scan_progress
        update_scan_progress(scan_id, {"status": "failed", "error": str(exc)})

    async with async_session() as session:
        repo = Repository(session)
        scan = await repo.get_scan(scan_id)
        findings = await repo.list_findings(scan_id=scan_id) if scan else []
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found after execution")
        return ScanResponse(
            id=scan.id, target=scan.target,
            target_type=scan.target_type if isinstance(scan.target_type, str) else scan.target_type.value,
            status=scan.status if isinstance(scan.status, str) else scan.status.value,
            profile=scan.profile or "quick",
            progress=scan.progress or 0.0, current_step=scan.current_step,
            project_id=scan.project_id, created_at=scan.created_at,
            updated_at=getattr(scan, 'updated_at', scan.created_at), findings_count=len(findings),
        )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, user: str = Depends(get_current_user)):
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session

    async with async_session() as session:
        repo = Repository(session)
        scan = await repo.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        findings = await repo.list_findings(scan_id=scan.id)
        return ScanResponse(
            id=scan.id, target=scan.target,
            target_type=scan.target_type if isinstance(scan.target_type, str) else scan.target_type.value,
            status=scan.status if isinstance(scan.status, str) else scan.status.value,
            profile=scan.profile or "quick",
            progress=scan.progress or 0.0, current_step=scan.current_step,
            project_id=scan.project_id, created_at=scan.created_at,
            updated_at=getattr(scan, 'updated_at', scan.created_at), findings_count=len(findings),
        )


@router.post("/{scan_id}/stop")
async def stop_scan(scan_id: str, user: str = Depends(get_current_user)):
    from bugfinder.engine.scheduler import ScanOrchestrator

    orchestrator = ScanOrchestrator()
    await orchestrator.stop_scan(scan_id)
    return {"success": True}
