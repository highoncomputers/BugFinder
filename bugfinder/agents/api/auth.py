from __future__ import annotations

from typing import Any

from bugfinder.agents.base import BaseAgent, AgentContext, AgentResult
from bugfinder.core.types import Severity, Confidence
from bugfinder.utils.http import get, post


class APIAuthAgent(BaseAgent):
    category = "api"
    name = "api_auth"

    async def execute(self, context: AgentContext) -> AgentResult:
        findings = []
        target = context.target
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port:
            base_url += f":{target.port}"

        sensitive_endpoints = ["/admin", "/api/admin", "/api/users", "/api/config", "/api/keys",
                               "/api/internal", "/api/v1/admin", "/api/v1/users", "/api/v1/config"]

        for endpoint in sensitive_endpoints:
            url = base_url + endpoint
            try:
                resp_no_auth = await get(url, timeout=10)
                status = resp_no_auth.status_code if hasattr(resp_no_auth, 'status_code') else 0
                if status == 200:
                    findings.append({
                        "title": f"API Endpoint Accessible Without Authentication: {endpoint}",
                        "description": f"Sensitive endpoint {endpoint} returns 200 without any auth headers.",
                        "severity": Severity.HIGH,
                        "confidence": Confidence.HIGH,
                        "category": "api",
                        "cwe_id": "306",
                        "owasp_category": "A01-Broken Access Control",
                        "cvss_score": 7.5,
                        "evidence": {"endpoint": endpoint, "status_without_auth": status},
                        "remediation": "Implement authentication for all API endpoints. Use token-based or session-based auth.",
                    })
                elif status == 403:
                    pass
            except Exception:
                pass

        return AgentResult(
            agent_name="api_auth",
            status="completed",
            findings=findings,
            summary=f"Checked {len(sensitive_endpoints)} endpoints, found {len(findings)} auth issues",
        )
