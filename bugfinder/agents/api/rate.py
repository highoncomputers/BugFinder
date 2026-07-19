from __future__ import annotations

import asyncio

from bugfinder.agents.base import AgentContext, AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity
from bugfinder.utils.http import get


class APIRateAgent(BaseAgent):
    category = "api"
    name = "rate"

    async def execute(self, context: AgentContext) -> AgentResult:
        findings = []
        target = context.target
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port:
            base_url += f":{target.port}"

        endpoints = ["/", "/api", "/api/v1", "/health", "/login", "/api/login"]
        statuses = []

        for endpoint in endpoints:
            url = base_url + endpoint
            try:
                tasks = [get(url, timeout=5) for _ in range(20)]
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                statuses_200 = sum(
                    1 for r in responses if not isinstance(r, Exception) and hasattr(r, "status_code") and r.status_code == 200
                )
                statuses_429 = sum(
                    1 for r in responses if not isinstance(r, Exception) and hasattr(r, "status_code") and r.status_code == 429
                )
                statuses.append(
                    {
                        "endpoint": endpoint,
                        "total": len(responses),
                        "success": statuses_200,
                        "rate_limited": statuses_429,
                    }
                )

                if statuses_429 == 0 and statuses_200 >= 18:
                    findings.append(
                        {
                            "title": "Missing API Rate Limiting",
                            "description": f"Endpoint {endpoint} returned {statuses_200}/200 from 20 concurrent requests without rate limiting (0 blocked).",
                            "severity": Severity.MEDIUM,
                            "confidence": Confidence.HIGH,
                            "category": "api",
                            "cwe_id": "770",
                            "owasp_category": "A04-Unrestricted Resource Consumption",
                            "cvss_score": 5.3,
                            "evidence": {
                                "endpoint": endpoint,
                                "requests": 20,
                                "successful": statuses_200,
                                "rate_limited": statuses_429,
                            },
                            "remediation": "Implement rate limiting (429 Too Many Requests) for API endpoints. Use token bucket or sliding window algorithm.",
                        }
                    )
                elif statuses_429 > 0:
                    findings.append(
                        {
                            "title": "API Rate Limiting Detected",
                            "description": f"Endpoint {endpoint} rate limited {statuses_429}/20 requests. Rate limiting is active.",
                            "severity": Severity.INFO,
                            "confidence": Confidence.HIGH,
                            "category": "api",
                            "cwe_id": "",
                            "owasp_category": "",
                            "cvss_score": 0.0,
                            "evidence": {"endpoint": endpoint, "rate_limited": statuses_429},
                            "remediation": "No action needed - rate limiting is properly configured.",
                        }
                    )
            except Exception:
                pass

        return AgentResult(
            agent_name="rate",
            status="completed",
            findings=findings,
            summary=f"Rate limit check on {len(endpoints)} endpoints, found {len(findings)} issues",
        )
