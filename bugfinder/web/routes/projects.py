from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from bugfinder.web.auth import get_current_user
from bugfinder.web.models import ProjectCreate, ProjectResponse

router = APIRouter()


@router.get("", response_model=list[ProjectResponse])
async def list_projects(user: str = Depends(get_current_user)):
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session

    async with async_session() as session:
        repo = Repository(session)
        projects = await repo.list_projects()
        result = []
        for p in projects:
            scans = await repo.list_scans(project_id=p.id)
            result.append(
                ProjectResponse(
                    id=p.id,
                    name=p.name,
                    description=p.description or "",
                    created_at=p.created_at,
                    updated_at=p.updated_at,
                    scan_count=len(scans),
                )
            )
        return result


@router.post("", response_model=ProjectResponse, status_code=201)
async def create_project(data: ProjectCreate, user: str = Depends(get_current_user)):
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session

    async with async_session() as session:
        repo = Repository(session)
        project = await repo.create_project(name=data.name, description=data.description)
        return ProjectResponse(
            id=project.id,
            name=project.name,
            description=project.description or "",
            created_at=project.created_at,
            updated_at=project.updated_at,
        )


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: str, user: str = Depends(get_current_user)):
    from bugfinder.database.repository import Repository
    from bugfinder.database.session import async_session

    async with async_session() as session:
        repo = Repository(session)
        project = await repo.get_project(project_id)
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        scans = await repo.list_scans(project_id=project.id)
        return ProjectResponse(
            id=project.id,
            name=project.name,
            description=project.description or "",
            created_at=project.created_at,
            updated_at=project.updated_at,
            scan_count=len(scans),
        )
