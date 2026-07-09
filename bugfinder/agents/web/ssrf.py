from __future__ import annotations

from urllib.parse import urlparse

import httpx

from bugfinder.agents.base import AgentResult, BaseAgent

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:22",
    "http://localhost:8080",
    "http://0.0.0.0:443",
    "file:///etc/passwd",
]


class SSRFAgent(BaseAgent):
    name = "web.ssrf"
    description = "Server-Side Request Forgery scanner"

    async def execute(self) -> AgentResult:
        base_url = self.context.target
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"

        findings = []
        headers = {"User-Agent": "BugFinder/0.1.0"}

        async with httpx.AsyncClient(timeout=30, follow_redirects=False, verify=False) as client:
            try:
                resp = await client.get(base_url, headers=headers)
                content = resp.text
            except Exception:
                return AgentResult(
                    agent_name=self.name,
                    status="completed",
                    summary="Could not fetch target for SSRF scanning",
                )

            import re

            params = re.findall(
                r'(?:url|path|redirect|return|next|file|load|read|view|doc|page)\s*=\s*["\']?([^"\'&\s]+)',
                content,
                re.IGNORECASE,
            )
            params = list(set(params))
            if not params:
                parsed = urlparse(base_url)
                if parsed.query:
                    params = [p.split("=")[0] for p in parsed.query.split("&") if "=" in p]

            for param in params[:5]:
                for payload in SSRF_PAYLOADS[:3]:
                    test_url = (
                        f"{base_url}?{param}={payload}" if "?" not in base_url else f"{base_url}&{param}={payload}"
                    )
                    try:
                        tr = await client.get(test_url, headers=headers, follow_redirects=False)
                        if tr.status_code in (200, 302, 301):
                            findings.append(
                                {
                                    "title": "Potential SSRF Detected",
                                    "description": f"Parameter '{param}' may be vulnerable to SSRF via {payload}",
                                    "severity": "high",
                                    "confidence": "needs_review",
                                    "category": "ssrf",
                                    "evidence": {
                                        "url": test_url,
                                        "parameter": param,
                                        "payload": payload,
                                        "status": tr.status_code,
                                        "location": tr.headers.get("location", ""),
                                    },
                                }
                            )
                    except Exception:
                        continue

        for f in findings:
            f["id"] = f"ssrf-{findings.index(f)}"
        summary = f"Tested {len(params)} params for SSRF, {len(findings)} potential issues"
        return AgentResult(
            agent_name=self.name,
            status="completed",
            findings=findings,
            summary=summary,
        )
