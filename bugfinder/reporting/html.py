from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from bugfinder import __version__

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#0d6efd",
    "info": "#6c757d",
}


def generate_html_report(
    target: str,
    target_type: str,
    findings: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    scan_duration: float = 0.0,
) -> str:
    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 99),
    )
    by_severity = {}
    for f in sorted_findings:
        sev = f.get("severity", "info")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    findings_rows = ""
    for i, f in enumerate(sorted_findings, 1):
        sev = f.get("severity", "info")
        color = SEVERITY_COLORS.get(sev, "#6c757d")
        evidence = f.get("evidence", {})
        ev_html = ""
        if evidence:
            ev_html = (
                "<div class='evidence'><pre>" + "\n".join(f"  {k}: {v}" for k, v in evidence.items()) + "</pre></div>"
            )

        findings_rows += f"""
        <div class="finding severity-{sev}">
            <div class="finding-header">
                <span class="severity-badge" style="background:{color}">{sev.upper()}</span>
                <span class="finding-confidence">{f.get("confidence", "needs_review")}</span>
                <h3>{i}. {f.get("title", "Untitled")}</h3>
            </div>
            <div class="finding-body">
                <p>{f.get("description", "")}</p>
                <div class="finding-meta">
                    <span>Category: {f.get("category", "general")}</span>
                    {f"<span>CWE: {f['cwe_id']}</span>" if f.get("cwe_id") else ""}
                    {f"<span>OWASP: {f['owasp_category']}</span>" if f.get("owasp_category") else ""}
                </div>
                {ev_html}
                {f'<div class="remediation"><strong>Remediation:</strong> {f["remediation"]}</div>' if f.get("remediation") else ""}
            </div>
        </div>"""

    severity_rows = ""
    for sev in ("critical", "high", "medium", "low", "info"):
        count = by_severity.get(sev, 0)
        if count:
            color = SEVERITY_COLORS.get(sev, "#6c757d")
            severity_rows += f"<tr><td style='color:{color}'>{sev.title()}</td><td>{count}</td></tr>"

    asset_rows = ""
    for a in assets[:50]:
        asset_rows += f"<tr><td>{a.get('name', a.get('id', ''))[:60]}</td><td>{a.get('asset_type', '')}</td><td>{str(a.get('value', ''))[:40]}</td></tr>"

    duration_str = _format_duration(scan_duration)
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BugFinder Report — {target[:60]}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #333; background: #f8f9fa; line-height: 1.6; }}
.container {{ max-width: 900px; margin: 0 auto; padding: 20px; }}
.header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); color: white; padding: 30px; border-radius: 8px; margin-bottom: 20px; }}
.header h1 {{ margin-bottom: 5px; }}
.header .meta {{ color: #a0a0b0; font-size: 14px; }}
.summary {{ background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
th {{ background: #f1f3f5; font-weight: 600; }}
.finding {{ background: white; border-radius: 8px; margin-bottom: 15px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); overflow: hidden; }}
.finding-header {{ padding: 15px; border-bottom: 1px solid #eee; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
.finding-header h3 {{ flex: 1; min-width: 200px; font-size: 16px; }}
.severity-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; color: white; font-size: 11px; font-weight: 700; letter-spacing: 0.5px; }}
.finding-confidence {{ font-size: 12px; color: #888; }}
.finding-body {{ padding: 15px; }}
.finding-body p {{ margin-bottom: 10px; }}
.finding-meta {{ display: flex; gap: 15px; font-size: 12px; color: #888; margin-bottom: 10px; flex-wrap: wrap; }}
.evidence {{ background: #f1f3f5; padding: 10px; border-radius: 4px; margin: 10px 0; overflow-x: auto; }}
.evidence pre {{ font-family: 'SF Mono', Monaco, monospace; font-size: 12px; white-space: pre-wrap; }}
.remediation {{ background: #d4edda; padding: 10px; border-radius: 4px; margin-top: 10px; font-size: 14px; }}
.footer {{ text-align: center; padding: 20px; color: #888; font-size: 12px; }}
.assets-table {{ max-height: 300px; overflow-y: auto; }}
@media print {{ .header {{ background: #1a1a2e !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }} }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>BugFinder Security Assessment</h1>
        <div class="meta">
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Type:</strong> {target_type} | <strong>Date:</strong> {now} | <strong>Duration:</strong> {duration_str}</p>
            <p><strong>Tool:</strong> BugFinder v{__version__}</p>
        </div>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <p>This assessment identified <strong>{len(findings)}</strong> security-related findings across <strong>{len(assets)}</strong> discovered assets.</p>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
            {severity_rows}
        </table>
    </div>

    <div class="summary">
        <h2>Asset Inventory</h2>
        <div class="assets-table">
        <table>
            <tr><th>Asset</th><th>Type</th><th>Value</th></tr>
            {asset_rows}
        </table>
        </div>
    </div>

    <h2>Findings</h2>
    {findings_rows}

    <div class="footer">
        <p>Generated by BugFinder v{__version__} | <a href="https://github.com/highoncomputers/BugFinder">GitHub</a></p>
    </div>
</div>
</body>
</html>"""


def _format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        m, s = divmod(int(seconds), 60)
        return f"{m}m {s}s"
    h, m = divmod(int(seconds), 3600)
    return f"{h}h {m}m"
