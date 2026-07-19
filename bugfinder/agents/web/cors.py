from __future__ import annotations

from bugfinder.agents.base import AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity
from bugfinder.utils.http import get


class CORSAgent(BaseAgent):
    category = "web"
    name = "cors"

    async def execute(self) -> AgentResult:
        findings = []
        target = self.context.target
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port:
            base_url += f":{target.port}"

        origins = [
            "https://evil.com",
            "null",
            "https://evil.com" + base_url,
            "https://" + target.hostname + ".evil.com",
        ]

        for origin in origins:
            try:
                resp = await get(
                    base_url,
                    headers={"Origin": origin},
                    timeout=10,
                )
                if hasattr(resp, "headers"):
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                    if acao == origin or acao == "*":
                        finding = {
                            "title": "CORS Misconfiguration",
                            "description": f"Server reflects Origin header in Access-Control-Allow-Origin: '{origin}'",
                            "severity": Severity.HIGH if origin != "*" else Severity.MEDIUM,
                            "confidence": Confidence.HIGH,
                            "category": "cors",
                            "cwe_id": "942",
                            "owasp_category": "A01-Broken Access Control",
                            "cvss_score": 6.1,
                            "evidence": {
                                "origin_tested": origin,
                                "access_control_allow_origin": acao,
                                "access_control_allow_credentials": acac,
                            },
                            "remediation": "Do not reflect the Origin header. Use a strict allowlist of trusted origins.",
                        }
                        if acac.lower() == "true":
                            finding["severity"] = Severity.CRITICAL
                            finding["title"] = "CORS Misconfiguration with Credentials"
                            finding["cvss_score"] = 8.6
                        findings.append(finding)
            except Exception:
                pass

        if not findings:
            try:
                resp = await get(base_url, timeout=10)
                if hasattr(resp, "headers"):
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    if acao == "*":
                        findings.append(
                            {
                                "title": "Wildcard CORS Origin",
                                "description": "Server allows all origins with wildcard '*'",
                                "severity": Severity.MEDIUM,
                                "confidence": Confidence.HIGH,
                                "category": "cors",
                                "cwe_id": "942",
                                "owasp_category": "A01-Broken Access Control",
                                "cvss_score": 5.0,
                                "evidence": {"access_control_allow_origin": "*"},
                                "remediation": "Use specific origins instead of wildcard. Never use '*' with credentials.",
                            }
                        )
            except Exception:
                pass

        return AgentResult(
            agent_name="cors",
            status="completed",
            findings=findings,
            summary=f"Found {len(findings)} CORS issues",
        )
