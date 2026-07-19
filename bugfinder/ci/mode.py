from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from typing import Any

from bugfinder.core.config import Settings

logger = logging.getLogger(__name__)


@dataclass
class CIResult:
    passed: bool
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    findings: list[dict[str, Any]] = field(default_factory=list)
    exit_code: int = 0


class CIMode:
    def __init__(self):
        self.settings = Settings()

    def evaluate_findings(
        self, findings: list[Any], fail_on: list[str] | None = None, max_critical: int = 0, max_high: int = 0, max_medium: int = 5
    ) -> CIResult:
        fail_on = fail_on or ["critical", "high"]

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        finding_dicts = []

        for f in findings:
            severity = ""
            if hasattr(f, "severity"):
                severity = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            elif isinstance(f, dict):
                severity = f.get("severity", "info")

            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            finding_dicts.append(
                {
                    "title": getattr(f, "title", "") or (isinstance(f, dict) and f.get("title", "")) or "",
                    "severity": severity,
                    "description": getattr(f, "description", "") or (isinstance(f, dict) and f.get("description", "")) or "",
                }
            )

        failed = False
        if "critical" in fail_on and severity_counts["critical"] > max_critical:
            failed = True
        if "high" in fail_on and severity_counts["high"] > max_high:
            failed = True
        if "medium" in fail_on and severity_counts["medium"] > max_medium:
            failed = True

        exit_code = 1 if failed else 0

        return CIResult(
            passed=not failed,
            total_findings=len(findings),
            critical=severity_counts["critical"],
            high=severity_counts["high"],
            medium=severity_counts["medium"],
            low=severity_counts["low"],
            info=severity_counts["info"],
            findings=finding_dicts,
            exit_code=exit_code,
        )

    def generate_junit_xml(self, result: CIResult) -> str:
        import xml.etree.ElementTree as ET
        from xml.dom import minidom

        testsuites = ET.Element("testsuites", name="BugFinder")
        testsuite = ET.SubElement(
            testsuites,
            "testsuite",
            name="BugFinder Security Scan",
            tests=str(result.total_findings),
            failures=str(result.critical + result.high),
        )

        for f in result.findings:
            testcase = ET.SubElement(testsuite, "testcase", classname=f.get("severity", "info"), name=f.get("title", "")[:200])

            if f.get("severity") in ("critical", "high"):
                ET.SubElement(testcase, "failure", message=f.get("description", "")[:200], type=f.get("severity", ""))

        rough_string = ET.tostring(testsuites, encoding="unicode")
        return minidom.parseString(rough_string).toprettyxml(indent="  ")

    def generate_sarif_output(self, result: CIResult, target: str = "") -> dict[str, Any]:
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "BugFinder", "version": "0.2.0"}},
                    "results": [],
                }
            ],
        }

        for f in result.findings:
            sarif["runs"][0]["results"].append(
                {
                    "ruleId": f.get("severity", "info"),
                    "message": {"text": f.get("title", "")},
                    "level": "error" if f.get("severity") in ("critical", "high") else "warning",
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": target},
                            },
                        }
                    ],
                }
            )

        return sarif

    def exit_with_code(self, result: CIResult):
        print("\nBugFinder CI Results:")
        print(f"  Total Findings: {result.total_findings}")
        print(f"  Critical: {result.critical}")
        print(f"  High: {result.high}")
        print(f"  Medium: {result.medium}")
        print(f"  Low: {result.low}")
        print(f"  Info: {result.info}")
        print(f"  Result: {'PASSED' if result.passed else 'FAILED'}")
        sys.exit(result.exit_code)
