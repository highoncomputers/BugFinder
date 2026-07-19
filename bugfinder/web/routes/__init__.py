from fastapi import APIRouter

from bugfinder.web.routes import (
    agents,
    auth,
    chat,
    comments,
    config,
    dashboard,
    exploit,
    exports,
    findings,
    graph,
    learn,
    plugins,
    projects,
    proxy,
    remediation,
    reports,
    scans,
    sse,
    teams,
)

router = APIRouter()
router.include_router(auth.router, tags=["auth"])
router.include_router(chat.router, prefix="/api", tags=["chat"])
router.include_router(config.router, prefix="/api", tags=["config"])
router.include_router(graph.router, prefix="/api", tags=["graph"])
router.include_router(exploit.router, prefix="/api", tags=["exploit"])
router.include_router(proxy.router, prefix="/api", tags=["proxy"])
router.include_router(remediation.router, prefix="/api", tags=["remediation"])
router.include_router(teams.router, prefix="/api/teams", tags=["teams"])
router.include_router(comments.router, prefix="/api", tags=["comments"])
router.include_router(plugins.router, prefix="/api/plugins", tags=["plugins"])
router.include_router(exports.router, prefix="/api", tags=["exports"])
router.include_router(learn.router, prefix="/api", tags=["learn"])
router.include_router(projects.router, prefix="/api/projects", tags=["projects"])
router.include_router(scans.router, prefix="/api/scans", tags=["scans"])
router.include_router(findings.router, prefix="/api/findings", tags=["findings"])
router.include_router(agents.router, prefix="/api/agents", tags=["agents"])
router.include_router(reports.router, prefix="/api/reports", tags=["reports"])
router.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"])
router.include_router(sse.router, prefix="/api", tags=["sse"])
