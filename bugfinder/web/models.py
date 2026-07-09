from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

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
    project_id: Optional[str] = None


class ScanResponse(BaseModel):
    id: str
    target: str
    target_type: str
    status: str
    profile: str
    progress: float
    current_step: Optional[str] = None
    project_id: Optional[str] = None
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
    category: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss_score: Optional[float] = None
    evidence: Any = None
    remediation: Optional[str] = None
    created_at: datetime


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None


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
