from __future__ import annotations

from typing import Any

from bugfinder.agents.base import BaseAgent, AgentContext, AgentResult
from bugfinder.core.types import Severity, Confidence
from bugfinder.utils.http import get


class SSTIAgent(BaseAgent):
    category = "web"
    name = "ssti"

    async def execute(self, context: AgentContext) -> AgentResult:
        findings = []
        target = context.target
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port:
            base_url += f":{target.port}"

        test_params = ["name", "username", "user", "search", "q", "page", "template", "view"]

        payloads = [
            ("{{7*7}}", "Jinja2/Twig"), ("${7*7}", "Freemarker"), ("#{7*7}", "Velocity"),
            ("*{7*7}", "EL"), ("{{7*'7'}}", "Jinja2 string"), ("<%= 7*7 %>", "ERB"),
        ]

        for param in test_params:
            for payload, engine in payloads:
                try:
                    resp = await get(base_url, params={param: payload}, timeout=10)
                    text = resp.text if hasattr(resp, 'text') else ""
                    if "49" in text or "777777" in text:
                        findings.append({
                            "title": f"Server-Side Template Injection ({engine})",
                            "description": f"Parameter '{param}' is vulnerable to {engine} SSTI with payload: {payload}",
                            "severity": Severity.CRITICAL,
                            "confidence": Confidence.HIGH,
                            "category": "ssti",
                            "cwe_id": "1336",
                            "owasp_category": "A03-Injection",
                            "cvss_score": 9.8,
                            "evidence": {"parameter": param, "payload": payload, "engine": engine},
                            "remediation": "Use output encoding and disable template execution in user input. Never render user input as templates.",
                        })
                except Exception:
                    pass

        return AgentResult(
            agent_name="ssti",
            status="completed" if findings else "completed",
            findings=findings,
            summary=f"Found {len(findings)} SSTI vulnerabilities",
        )
