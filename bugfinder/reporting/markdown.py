from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from bugfinder import __version__

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def generate_markdown_report(
    target: str,
    target_type: str,
    findings: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    scan_duration: float = 0.0,
) -> str:
    lines = []

    lines.append("# BugFinder Security Assessment Report")
    lines.append("")
    lines.append(f"**Target**: `{target}`")
    lines.append(f"**Type**: {target_type}")
    lines.append(f"**Date**: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"**Tool**: BugFinder v{__version__}")
    lines.append(f"**Duration**: {_format_duration(scan_duration)}")
    lines.append("")

    lines.append("---")
    lines.append("## Executive Summary")
    lines.append("")

    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 99),
    )
    by_severity = {}
    for f in sorted_findings:
        sev = f.get("severity", "info")
        by_severity.setdefault(sev, 0)
        by_severity[sev] += 1

    total = len(findings)
    lines.append(f"This assessment identified **{total}** security-related findings.")
    lines.append("")

    if by_severity:
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ("critical", "high", "medium", "low", "info"):
            count = by_severity.get(sev, 0)
            icon = SEVERITY_ICONS.get(sev, "")
            lines.append(f"| {icon} {sev.title()} | {count} |")
        lines.append("")

    lines.append("---")
    lines.append("## Asset Inventory")
    lines.append("")
    lines.append(f"Discovered **{len(assets)}** assets during assessment.")
    lines.append("")

    if assets:
        lines.append("| Asset | Type | Value |")
        lines.append("|-------|------|-------|")
        for a in assets[:50]:
            name = a.get("name", a.get("id", "unknown"))
            atype = a.get("asset_type", "unknown")
            value = str(a.get("value", ""))[:60]
            lines.append(f"| {name} | {atype} | {value} |")
        if len(assets) > 50:
            lines.append(f"| ... | ({len(assets) - 50} more) | |")
        lines.append("")

    lines.append("---")
    lines.append("## Findings")
    lines.append("")

    if not findings:
        lines.append("No findings were identified during this assessment.")
        lines.append("")

    for i, f in enumerate(sorted_findings, 1):
        sev = f.get("severity", "info")
        icon = SEVERITY_ICONS.get(sev, "")
        title = f.get("title", "Untitled Finding")
        lines.append(f"### {i}. {icon} {title}")
        lines.append("")
        lines.append(f"- **Severity**: {sev.upper()}")
        lines.append(f"- **Confidence**: {f.get('confidence', 'needs_review')}")
        lines.append(f"- **Category**: {f.get('category', 'general')}")

        cwe = f.get("cwe_id")
        owasp = f.get("owasp_category")
        if cwe:
            lines.append(f"- **CWE**: {cwe}")
        if owasp:
            lines.append(f"- **OWASP**: {owasp}")

        lines.append("")

        desc = f.get("description", "")
        if desc:
            lines.append(f"**Description**: {desc}")
            lines.append("")

        evidence = f.get("evidence", {})
        if evidence:
            lines.append("**Evidence**:")
            lines.append("")
            lines.append("```")
            for k, v in evidence.items():
                lines.append(f"  {k}: {v}")
            lines.append("```")
            lines.append("")

        biz_impact = f.get("business_impact")
        if biz_impact:
            lines.append(f"**Business Impact**: {biz_impact}")
            lines.append("")

        remediation = f.get("remediation")
        if remediation:
            lines.append(f"**Remediation**: {remediation}")
            lines.append("")

        if f.get("confidence") in ("needs_review",):
            lines.append("> ⚠️ This finding requires manual verification.")
            lines.append("")

        lines.append("---")
        lines.append("")

    lines.append("## Risk Matrix")
    lines.append("")
    lines.append("| Severity | Count | Priority |")
    lines.append("|----------|-------|----------|")
    priority_map = {
        "critical": "Immediate",
        "high": "Urgent",
        "medium": "High",
        "low": "Medium",
        "info": "Low",
    }
    for sev in ("critical", "high", "medium", "low", "info"):
        count = by_severity.get(sev, 0)
        if count > 0:
            lines.append(f"| {sev.title()} | {count} | {priority_map.get(sev, '')} |")
    lines.append("")

    lines.append("---")
    lines.append("## References")
    lines.append("")
    lines.append("- [OWASP Top 10](https://owasp.org/www-project-top-ten/)")
    lines.append("- [CWE Common Weakness Enumeration](https://cwe.mitre.org/)")
    lines.append("- [BugFinder Documentation](https://github.com/highoncomputers/BugFinder)")
    lines.append("")
    lines.append("---")
    lines.append("*Report generated by BugFinder v" + __version__ + "*")

    return "\n".join(lines)


def _format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        m, s = divmod(int(seconds), 60)
        return f"{m}m {s}s"
    h, m = divmod(int(seconds), 3600)
    return f"{h}h {m}m"
