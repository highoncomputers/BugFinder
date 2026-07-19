from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FindingDiff:
    new_findings: list[dict[str, Any]] = field(default_factory=list)
    fixed_findings: list[dict[str, Any]] = field(default_factory=list)
    regressed_findings: list[dict[str, Any]] = field(default_factory=list)
    unchanged_findings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def total_changes(self) -> int:
        return len(self.new_findings) + len(self.fixed_findings) + len(self.regressed_findings)


def diff_findings(previous_findings: list[Any], current_findings: list[Any]) -> FindingDiff:
    prev_map: dict[str, Any] = {}
    for f in previous_findings:
        title = getattr(f, "title", "") or (isinstance(f, dict) and f.get("title", ""))
        if title:
            prev_map[title] = f

    curr_map: dict[str, Any] = {}
    for f in current_findings:
        title = getattr(f, "title", "") or (isinstance(f, dict) and f.get("title", ""))
        if title:
            curr_map[title] = f

    diff = FindingDiff()

    for title, f in curr_map.items():
        f_dict = _to_dict(f)
        if title not in prev_map:
            diff.new_findings.append(f_dict)
        else:
            prev = prev_map[title]
            prev_status = getattr(prev, "status", "") or (isinstance(prev, dict) and prev.get("status", ""))
            curr_status = getattr(f, "status", "") or (isinstance(f, dict) and f.get("status", ""))
            prev_severity = str(getattr(prev, "severity", "")) or (isinstance(prev, dict) and str(prev.get("severity", "")))
            curr_severity = str(getattr(f, "severity", "")) or (isinstance(f, dict) and str(f.get("severity", "")))

            if prev_status != "fixed" and curr_status == "fixed":
                diff.fixed_findings.append(f_dict)
            elif curr_severity != prev_severity and _severity_value(curr_severity) > _severity_value(prev_severity):
                diff.regressed_findings.append(f_dict)
            else:
                diff.unchanged_findings.append(f_dict)

    for title, f in prev_map.items():
        if title not in curr_map:
            diff.fixed_findings.append(_to_dict(f))

    return diff


def _to_dict(f: Any) -> dict[str, Any]:
    if isinstance(f, dict):
        return f
    return {
        "title": getattr(f, "title", ""),
        "description": getattr(f, "description", ""),
        "severity": str(getattr(f, "severity", "")),
        "status": str(getattr(f, "status", "")),
        "category": getattr(f, "category", ""),
    }


def _severity_value(s: str) -> int:
    mapping = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return mapping.get(s.lower(), 0)
