from __future__ import annotations

from bugfinder.agents.base import AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity
from bugfinder.utils.http import get


class APIFuzzAgent(BaseAgent):
    category = "api"
    name = "fuzz"

    async def execute(self) -> AgentResult:
        findings = []
        target = self.context.target
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port:
            base_url += f":{target.port}"

        common_params = [
            "id",
            "page",
            "limit",
            "offset",
            "sort",
            "order",
            "filter",
            "search",
            "q",
            "debug",
            "test",
            "admin",
            "token",
            "key",
            "api_key",
            "secret",
            "password",
            "username",
            "email",
            "file",
            "path",
            "url",
            "callback",
            "redirect",
            "next",
            "format",
            "type",
            "action",
            "method",
            "function",
            "cmd",
            "command",
            "exec",
        ]

        for param in common_params[:10]:
            try:
                resp = await get(base_url, params={param: "test"}, timeout=10)
                status = resp.status_code if hasattr(resp, "status_code") else 0
                if status == 200:
                    findings.append(
                        {
                            "title": f"API Parameter '{param}' Accepted",
                            "description": f"API endpoint accepts unexpected parameter '{param}', which may indicate undocumented functionality.",
                            "severity": Severity.LOW,
                            "confidence": Confidence.MEDIUM,
                            "category": "api",
                            "cwe_id": "200",
                            "owasp_category": "A01-Broken Access Control",
                            "cvss_score": 3.5,
                            "evidence": {"parameter": param, "url": base_url, "status": status},
                            "remediation": "Restrict API parameters to documented allowlist. Validate all input parameters.",
                        }
                    )
            except Exception:
                pass

        return AgentResult(
            agent_name="fuzz",
            status="completed",
            findings=findings,
            summary=f"Fuzzed {len(common_params[:10])} parameters, found {len(findings)} accepted",
        )
