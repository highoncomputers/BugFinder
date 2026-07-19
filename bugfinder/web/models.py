from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""


class ProjectResponse(BaseModel):
    id: str
    name: str
    description: str
    created_at: datetime
    updated_at: datetime
    scan_count: int = 0


class ScanCreate(BaseModel):
    target: str = Field(..., min_length=1)
    profile: str = "quick"
    project_id: str | None = None


class ScanResponse(BaseModel):
    id: str
    target: str
    target_type: str
    status: str
    profile: str
    progress: float
    current_step: str | None = None
    project_id: str | None = None
    created_at: datetime
    updated_at: datetime
    findings_count: int = 0


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    title: str
    description: str
    severity: str
    confidence: str
    status: str
    category: str | None = None
    cwe_id: str | None = None
    owasp_category: str | None = None
    cvss_score: float | None = None
    evidence: Any = None
    remediation: str | None = None
    created_at: datetime


class FindingUpdate(BaseModel):
    status: str | None = None
    severity: str | None = None


class AgentResponse(BaseModel):
    name: str
    category: str
    description: str
    enabled: bool = True


class DashboardStats(BaseModel):
    total_projects: int
    total_scans: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    scans_by_status: dict[str, int]
    recent_scans: list[ScanResponse]


class HealthResponse(BaseModel):
    status: str
    version: str
    database: str
