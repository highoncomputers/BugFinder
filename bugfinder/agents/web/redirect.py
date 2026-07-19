from __future__ import annotations

from bugfinder.agents.base import AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity
from bugfinder.utils.http import get


class OpenRedirectAgent(BaseAgent):
    category = "web"
    name = "redirect"

    async def execute(self) -> AgentResult:
        findings = []
        target = self.context.target
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port:
            base_url += f":{target.port}"

        redirect_params = [
            "redirect",
            "url",
            "next",
            "return",
            "return_to",
            "returnUrl",
            "r",
            "u",
            "to",
            "dest",
            "destination",
            "goto",
            "target",
            "view",
            "page",
            "ref",
            "referer",
            "logout",
        ]

        test_urls = [
            "https://evil.com",
            "//evil.com",
            "https://evil.com" + target.hostname,
            "http://evil.com",
            "///evil.com",
            "https://evil.com/@" + target.hostname,
        ]

        for param in redirect_params:
            for test_url in test_urls:
                try:
                    resp = await get(base_url, params={param: test_url}, timeout=10, follow_redirects=False)
                    status = resp.status_code if hasattr(resp, "status_code") else 0
                    location = ""
                    if hasattr(resp, "headers"):
                        location = resp.headers.get("Location", "")

                    if status in (301, 302, 303, 307, 308) and "evil.com" in location:
                        findings.append(
                            {
                                "title": "Open Redirect Vulnerability",
                                "description": f"Parameter '{param}' redirects to external URL: {test_url}",
                                "severity": Severity.MEDIUM,
                                "confidence": Confidence.HIGH,
                                "category": "open-redirect",
                                "cwe_id": "601",
                                "owasp_category": "A01-Broken Access Control",
                                "cvss_score": 6.1,
                                "evidence": {
                                    "parameter": param,
                                    "test_url": test_url,
                                    "redirect_url": location,
                                    "status_code": status,
                                },
                                "remediation": "Validate redirect URLs against an allowlist. Avoid user-controlled redirects.",
                            }
                        )
                except Exception:
                    pass

        return AgentResult(
            agent_name="redirect",
            status="completed",
            findings=findings,
            summary=f"Found {len(findings)} open redirects",
        )
