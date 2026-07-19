from __future__ import annotations

from typing import Any

from bugfinder.core.types import Severity
from bugfinder.workflow import Phase


class PhaseReporter:
    @staticmethod
    def phase_summary(phase: Phase, findings: list[Any]) -> dict[str, Any]:
        severity_counts = {s.value: 0 for s in Severity}
        for f in findings:
            sev = ""
            if hasattr(f, "severity"):
                sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            elif isinstance(f, dict):
                sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "phase": phase.value,
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "categories": list(
                set(
                    f.category if hasattr(f, "category") else (isinstance(f, dict) and f.get("category", ""))
                    for f in findings
                    if hasattr(f, "category") or isinstance(f, dict)
                )
            ),
        }

    @staticmethod
    def workflow_summary(progress: list[Any], all_findings: list[Any]) -> dict[str, Any]:
        phase_summaries = {}
        for wp in progress:
            phase_findings = [
                f
                for f in all_findings
                if getattr(wp, "phase", None) and (getattr(f, "scan_id", None) == getattr(wp, "scan_id", None) or True)
            ]
            phase_summaries[wp.phase.value] = PhaseReporter.phase_summary(
                Phase(wp.phase.value) if isinstance(wp.phase, str) else wp.phase,
                phase_findings,
            )

        severity_counts = {s.value: 0 for s in Severity}
        for f in all_findings:
            sev = ""
            if hasattr(f, "severity"):
                sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            elif isinstance(f, dict):
                sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "total_findings": len(all_findings),
            "by_severity": severity_counts,
            "phases": phase_summaries,
            "recommendation": PhaseReporter._recommendation(severity_counts),
        }

    @staticmethod
    def _recommendation(severity_counts: dict[str, int]) -> str:
        if severity_counts.get("critical", 0) > 0:
            return "Immediate action required: Critical vulnerabilities detected."
        if severity_counts.get("high", 0) > 0:
            return "High priority: Address high-severity findings as soon as possible."
        if severity_counts.get("medium", 0) > 0:
            return "Medium priority: Review medium-severity findings in the next sprint."
        return "Low priority: No critical or high-severity findings detected."
