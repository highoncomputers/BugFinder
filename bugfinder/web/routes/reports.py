from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from bugfinder.web.auth import get_current_user

router = APIRouter()


@router.get("/{scan_id}")
async def get_report(
    scan_id: str,
    fmt: str = Query("markdown", alias="format"),
    user: str = Depends(get_current_user),
):
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session

    async with async_session() as session:
        repo = Repository(session)
        scan = await repo.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        findings = await repo.list_findings(scan_id=scan_id)
        assets = await repo.list_assets(scan_id=scan_id)

    if fmt == "markdown":
        from bugfinder.reporting.markdown import generate_markdown_report

        report = generate_markdown_report(
            target=scan.target,
            scan_id=scan_id,
            findings=findings,
            assets=assets,
            scan_start=scan.created_at,
            scan_end=scan.updated_at,
        )
        return PlainTextResponse(report, media_type="text/markdown")

    elif fmt == "html":
        from bugfinder.reporting.html import generate_html_report

        report = generate_html_report(
            target=scan.target,
            scan_id=scan_id,
            findings=findings,
            assets=assets,
        )
        return HTMLResponse(report)

    elif fmt == "json":
        from bugfinder.reporting.json_report import generate_json_report

        report = generate_json_report(
            target=scan.target,
            scan_id=scan_id,
            findings=findings,
            assets=assets,
        )
        return JSONResponse(report)

    raise HTTPException(status_code=400, detail=f"Unsupported format: {fmt}")
