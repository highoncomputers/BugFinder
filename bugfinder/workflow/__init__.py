from __future__ import annotations

from enum import StrEnum


class Phase(StrEnum):
    RECON = "recon"
    VULN_DETECTION = "vuln_detection"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"


class PhaseStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
