from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bugfinder.database.models import (
    AgentResult,
    Asset,
    Finding,
    Project,
    ScanSession,
)


class Repository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def commit(self) -> None:
        await self.session.commit()

    async def rollback(self) -> None:
        await self.session.rollback()

    # Project
    async def create_project(self, name: str, description: str | None = None) -> Project:
        project = Project(name=name, description=description)
        self.session.add(project)
        await self.commit()
        return project

    async def get_project(self, project_id: str) -> Project | None:
        return await self.session.get(Project, project_id)

    async def list_projects(self) -> list[Project]:
        result = await self.session.execute(select(Project).order_by(Project.updated_at.desc()))
        return list(result.scalars().all())

    # ScanSession
    async def create_scan(
        self, target: str, target_type: str, project_id: str | None = None
    ) -> ScanSession:
        scan = ScanSession(target=target, target_type=target_type, project_id=project_id)
        self.session.add(scan)
        await self.commit()
        return scan

    async def get_scan(self, scan_id: str) -> ScanSession | None:
        return await self.session.get(ScanSession, scan_id)

    async def update_scan(self, scan_id: str, **kwargs: Any) -> ScanSession | None:
        scan = await self.get_scan(scan_id)
        if scan:
            for key, value in kwargs.items():
                setattr(scan, key, value)
            await self.commit()
        return scan

    async def list_scans(self, project_id: str | None = None) -> list[ScanSession]:
        stmt = select(ScanSession)
        if project_id:
            stmt = stmt.where(ScanSession.project_id == project_id)
        result = await self.session.execute(stmt.order_by(ScanSession.created_at.desc()))
        return list(result.scalars().all())

    # Finding
    async def create_finding(
        self,
        scan_id: str,
        title: str,
        description: str | None = None,
        severity: str = "medium",
        **kwargs: Any,
    ) -> Finding:
        finding = Finding(
            scan_id=scan_id, title=title, description=description, severity=severity, **kwargs
        )
        self.session.add(finding)
        await self.commit()
        return finding

    async def get_finding(self, finding_id: str) -> Finding | None:
        return await self.session.get(Finding, finding_id)

    async def list_findings(self, scan_id: str, severity: str | None = None) -> list[Finding]:
        stmt = select(Finding).where(Finding.scan_id == scan_id)
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        result = await self.session.execute(
            stmt.order_by(Finding.severity, Finding.discovered_at.desc())
        )
        return list(result.scalars().all())

    # Asset
    async def create_asset(self, scan_id: str, name: str, asset_type: str, **kwargs: Any) -> Asset:
        asset = Asset(scan_id=scan_id, name=name, asset_type=asset_type, **kwargs)
        self.session.add(asset)
        await self.commit()
        return asset

    async def list_assets(self, scan_id: str) -> list[Asset]:
        result = await self.session.execute(select(Asset).where(Asset.scan_id == scan_id))
        return list(result.scalars().all())

    # AgentResult
    async def create_agent_result(self, scan_id: str, agent_name: str) -> AgentResult:
        ar = AgentResult(scan_id=scan_id, agent_name=agent_name)
        self.session.add(ar)
        await self.commit()
        return ar

    async def update_agent_result(self, agent_result_id: str, **kwargs: Any) -> AgentResult | None:
        ar = await self.session.get(AgentResult, agent_result_id)
        if ar:
            for key, value in kwargs.items():
                setattr(ar, key, value)
            await self.commit()
        return ar
