from __future__ import annotations

import httpx

from bugfinder.agents.base import AgentResult, BaseAgent

SQLI_PAYLOADS = ["'", '"', "1=1--", "' OR '1'='1", '" OR "1"="1', "1 UNION SELECT 1"]


SQLI_ERRORS = [
    "sql",
    "mysql",
    "sqlite",
    "postgresql",
    "oracle",
    "you have an error in your sql",
    "unclosed quotation mark",
    "sql syntax",
    "warning: mysql",
    "odbc",
    "driver",
]


class SQLiAgent(BaseAgent):
    name = "web.sqli"
    description = "SQL injection vulnerability scanner"

    async def execute(self) -> AgentResult:
        base_url = self.context.target
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"

        findings = []
        headers = {"User-Agent": "BugFinder/0.1.0"}

        async with httpx.AsyncClient(timeout=30, follow_redirects=True, verify=False) as client:
            try:
                resp = await client.get(base_url, headers=headers)
            except Exception:
                return AgentResult(
                    agent_name=self.name,
                    status="completed",
                    summary="Could not fetch target for SQLi scanning",
                )

            import re
            from urllib.parse import urlparse

            parsed = urlparse(base_url)
            params = []
            if parsed.query:
                params = [p.split("=")[0] for p in parsed.query.split("&") if "=" in p]

            if not params:
                forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'](.*?)</form>', resp.text, re.DOTALL)
                for action, body in forms:
                    inputs = re.findall(r'name=["\']([^"\']+)["\']', body)
                    params.extend(inputs)
                if not params:
                    return AgentResult(
                        agent_name=self.name,
                        status="completed",
                        summary="No input parameters found to test",
                    )

            for param in params[:5]:
                for payload in SQLI_PAYLOADS[:3]:
                    injection_url = f"{base_url}?{param}={payload}"
                    try:
                        test_resp = await client.get(injection_url, headers=headers)
                        body = test_resp.text.lower()
                        if any(err in body for err in SQLI_ERRORS):
                            findings.append(
                                {
                                    "title": "Potential SQL Injection Detected",
                                    "description": f"Parameter '{param}' shows SQL error with payload: {payload}",
                                    "severity": "critical",
                                    "confidence": "needs_review",
                                    "category": "sqli",
                                    "evidence": {
                                        "url": injection_url,
                                        "parameter": param,
                                        "payload": payload,
                                        "status": test_resp.status_code,
                                        "error_snippet": self._extract_error_context(test_resp.text),
                                    },
                                }
                            )
                    except Exception:
                        continue

        for f in findings:
            f["id"] = f"sqli-{findings.index(f)}"

        summary = f"Tested {len(params)} parameters, {len(findings)} potential SQLi issues"
        return AgentResult(
            agent_name=self.name,
            status="completed",
            findings=findings,
            summary=summary,
        )

    def _extract_error_context(self, text: str) -> str:
        for marker in SQLI_ERRORS:
            idx = text.lower().find(marker)
            if idx >= 0:
                start = max(0, idx - 50)
                end = min(len(text), idx + 150)
                return text[start:end]
        return ""
