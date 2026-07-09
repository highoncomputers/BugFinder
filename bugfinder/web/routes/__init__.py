from fastapi import APIRouter

from bugfinder.web.routes import projects, scans, findings, agents, reports, dashboard, sse, auth

router = APIRouter()
router.include_router(auth.router, tags=["auth"])
router.include_router(projects.router, prefix="/api/projects", tags=["projects"])
router.include_router(scans.router, prefix="/api/scans", tags=["scans"])
router.include_router(findings.router, prefix="/api/findings", tags=["findings"])
router.include_router(agents.router, prefix="/api/agents", tags=["agents"])
router.include_router(reports.router, prefix="/api/reports", tags=["reports"])
router.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"])
router.include_router(sse.router, prefix="/api", tags=["sse"])
