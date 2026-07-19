from __future__ import annotations

import asyncio

from bugfinder.agents.base import AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity
from bugfinder.utils.http import post


class RaceConditionAgent(BaseAgent):
    category = "web"
    name = "race"

    async def execute(self) -> AgentResult:
        findings = []
        target = self.context.target
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port:
            base_url += f":{target.port}"

        race_endpoints = [
            ("/api/checkout", "POST"),
            ("/api/order", "POST"),
            ("/api/transfer", "POST"),
            ("/api/withdraw", "POST"),
            ("/api/vote", "POST"),
            ("/api/coupon/redeem", "POST"),
            ("/api/gift/redeem", "POST"),
            ("/api/referral/claim", "POST"),
            ("/cart/add", "POST"),
            ("/checkout", "POST"),
        ]

        body = {"concurrent_requests": 10}
        headers = {"Content-Type": "application/json"}

        for path, method in race_endpoints:
            url = base_url + path
            try:
                tasks = [post(url, json=body, headers=headers, timeout=5) for _ in range(10)]
                responses = await asyncio.gather(*tasks, return_exceptions=True)

                success_count = sum(
                    1 for r in responses if not isinstance(r, Exception) and hasattr(r, "status_code") and r.status_code == 200
                )

                if success_count >= 6:
                    findings.append(
                        {
                            "title": "Potential Race Condition",
                            "description": f"Endpoint {path} returned {success_count}/200 success responses from {len(responses)} concurrent requests.",
                            "severity": Severity.HIGH,
                            "confidence": Confidence.LOW,
                            "category": "race-condition",
                            "cwe_id": "362",
                            "owasp_category": "A01-Broken Access Control",
                            "cvss_score": 6.3,
                            "evidence": {"endpoint": path, "concurrent_requests": len(responses), "success_count": success_count},
                            "remediation": "Use database transactions, pessimistic locking, or idempotency tokens to prevent race conditions.",
                        }
                    )
            except Exception:
                pass

        return AgentResult(
            agent_name="race",
            status="completed",
            findings=findings,
            summary=f"Found {len(findings)} potential race conditions",
        )
