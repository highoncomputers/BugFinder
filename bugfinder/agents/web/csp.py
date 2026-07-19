from __future__ import annotations

from bugfinder.agents.base import AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity
from bugfinder.utils.http import get


class CSPAgent(BaseAgent):
    category = "web"
    name = "csp"

    async def execute(self) -> AgentResult:
        findings = []
        target = self.context.target
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port:
            base_url += f":{target.port}"

        resp = await get(base_url, timeout=10)
        csp = ""
        if hasattr(resp, "headers"):
            csp = resp.headers.get("Content-Security-Policy", "")

        if not csp:
            findings.append(
                {
                    "title": "Missing Content-Security-Policy Header",
                    "description": "No CSP header found. This increases risk of XSS and data injection attacks.",
                    "severity": Severity.MEDIUM,
                    "confidence": Confidence.HIGH,
                    "category": "csp",
                    "cwe_id": "1021",
                    "owasp_category": "A05-Security Misconfiguration",
                    "cvss_score": 5.0,
                    "evidence": {"header": "Content-Security-Policy", "value": "missing"},
                    "remediation": "Implement a Content-Security-Policy header starting with script-src and object-src restrictions.",
                }
            )
            return AgentResult(
                agent_name="csp",
                status="completed",
                findings=findings,
                summary="Missing CSP header",
            )

        issues = []

        if "unsafe-inline" in csp:
            issues.append(
                {
                    "title": "CSP Allows 'unsafe-inline'",
                    "description": "CSP allows inline script/style execution, reducing XSS protection.",
                    "severity": Severity.HIGH,
                    "confidence": Confidence.HIGH,
                    "category": "csp",
                    "cwe_id": "1021",
                    "owasp_category": "A05-Security Misconfiguration",
                    "cvss_score": 6.1,
                    "evidence": {"directive": "unsafe-inline"},
                    "remediation": "Remove 'unsafe-inline' and use nonces or hashes for inline scripts.",
                }
            )

        if "unsafe-eval" in csp:
            issues.append(
                {
                    "title": "CSP Allows 'unsafe-eval'",
                    "description": "CSP allows eval(), reducing XSS protection.",
                    "severity": Severity.MEDIUM,
                    "confidence": Confidence.HIGH,
                    "category": "csp",
                    "cwe_id": "1021",
                    "owasp_category": "A05-Security Misconfiguration",
                    "cvss_score": 5.3,
                    "evidence": {"directive": "unsafe-eval"},
                    "remediation": "Remove 'unsafe-eval' and refactor code not to use eval().",
                }
            )

        if "*" in csp and ("script-src" in csp or "frame-src" in csp):
            issues.append(
                {
                    "title": "CSP Wildcard in Restricted Directives",
                    "description": "CSP uses wildcard '*' in script-src or frame-src, allowing any source.",
                    "severity": Severity.HIGH,
                    "confidence": Confidence.HIGH,
                    "category": "csp",
                    "cwe_id": "1021",
                    "owasp_category": "A05-Security Misconfiguration",
                    "cvss_score": 7.5,
                    "evidence": {
                        "directive": "script-src *" if "*" in csp.split("script-src")[-1].split(";")[0] else "frame-src *"
                    },
                    "remediation": "Remove wildcard from restricted directives. Specify exact trusted origins.",
                }
            )

        if "frame-ancestors" not in csp and "frame-src" not in csp:
            issues.append(
                {
                    "title": "CSP Missing frame-ancestors Directive",
                    "description": "No frame-ancestors directive allows framing by any origin (clickjacking).",
                    "severity": Severity.MEDIUM,
                    "confidence": Confidence.HIGH,
                    "category": "csp",
                    "cwe_id": "1021",
                    "owasp_category": "A05-Security Misconfiguration",
                    "cvss_score": 4.3,
                    "evidence": {"missing_directive": "frame-ancestors"},
                    "remediation": "Add 'frame-ancestors' directive with specific allowed origins.",
                }
            )

        findings.extend(issues)

        return AgentResult(
            agent_name="csp",
            status="completed",
            findings=findings,
            summary=f"Analyzed CSP, found {len(findings)} issues",
        )
