from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from bugfinder import __version__
from bugfinder.web.config import WebSettings
from bugfinder.web.routes import router

logger = logging.getLogger(__name__)

HERE = Path(__file__).parent
TEMPLATES_DIR = HERE / "templates"
STATIC_DIR = HERE / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("BugFinder Web UI starting up")
    from bugfinder.database.session import init_db
    await init_db()
    yield
    from bugfinder.database.session import close_db
    await close_db()
    logger.info("BugFinder Web UI shutting down")


def create_app() -> FastAPI:
    settings = WebSettings()
    app = FastAPI(
        title="BugFinder",
        description="AI-powered autonomous bug bounty assistant and security assessment platform",
        version=__version__,
        lifespan=lifespan,
    )

    app.state.settings = settings

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    app.include_router(router)

    @app.get("/health")
    async def health():
        from bugfinder.database.session import async_session
        try:
            async with async_session() as session:
                from sqlalchemy import text
                await session.execute(text("SELECT 1"))
            db_status = "connected"
        except Exception as e:
            db_status = f"error: {e}"

        return {
            "status": "ok",
            "version": __version__,
            "database": db_status,
        }

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        return templates.TemplateResponse("index.html", {"request": request, "version": __version__})

    @app.get("/scans", response_class=HTMLResponse)
    async def scans_page(request: Request):
        return templates.TemplateResponse("scans.html", {"request": request, "version": __version__})

    @app.get("/scans/{scan_id}", response_class=HTMLResponse)
    async def scan_detail(request: Request, scan_id: int):
        return templates.TemplateResponse("scan_detail.html", {"request": request, "scan_id": scan_id, "version": __version__})

    @app.get("/findings", response_class=HTMLResponse)
    async def findings_page(request: Request):
        return templates.TemplateResponse("findings.html", {"request": request, "version": __version__})

    @app.get("/findings/{finding_id}", response_class=HTMLResponse)
    async def finding_detail(request: Request, finding_id: int):
        return templates.TemplateResponse("finding_detail.html", {"request": request, "finding_id": finding_id, "version": __version__})

    @app.get("/projects", response_class=HTMLResponse)
    async def projects_page(request: Request):
        return templates.TemplateResponse("projects.html", {"request": request, "version": __version__})

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        return templates.TemplateResponse("login.html", {"request": request, "version": __version__})

    @app.exception_handler(404)
    async def not_found(request: Request, exc):
        return templates.TemplateResponse("404.html", {"request": request, "version": __version__}, status_code=404)

    @app.exception_handler(500)
    async def server_error(request: Request, exc):
        return templates.TemplateResponse("500.html", {"request": request, "version": __version__}, status_code=500)

    return app


app = create_app()


def main():
    import uvicorn
    settings = WebSettings()
    uvicorn.run(
        "bugfinder.web.app:app",
        host=settings.web_host,
        port=settings.web_port,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
