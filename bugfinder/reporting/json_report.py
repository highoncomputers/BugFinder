from __future__ import annotations

from datetime import UTC
from typing import Any


def generate_json_report(
    target: str,
    target_type: str,
    findings: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    scan_duration: float = 0.0,
) -> str:
    import json
    from datetime import datetime

    from bugfinder import __version__

    report = {
        "tool": "BugFinder",
        "version": __version__,
        "target": target,
        "target_type": target_type,
        "date": datetime.now(UTC).isoformat(),
        "duration_seconds": scan_duration,
        "summary": {
            "total_findings": len(findings),
            "total_assets": len(assets),
            "by_severity": {},
        },
        "findings": findings,
        "assets": assets,
    }
    for f in findings:
        sev = f.get("severity", "info")
        report["summary"]["by_severity"][sev] = report["summary"]["by_severity"].get(sev, 0) + 1

    return json.dumps(report, indent=2, default=str)
