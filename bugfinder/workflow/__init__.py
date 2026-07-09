from __future__ import annotations

from enum import Enum


class Phase(str, Enum):
    RECON = "recon"
    VULN_DETECTION = "vuln_detection"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"


class PhaseStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
