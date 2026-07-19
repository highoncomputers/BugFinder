from __future__ import annotations

from urllib.parse import urljoin, urlparse

import httpx

from bugfinder.agents.base import AgentResult, BaseAgent

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
]


class XSSAgent(BaseAgent):
    name = "web.xss"
    description = "Cross-Site Scripting vulnerability scanner"

    async def execute(self) -> AgentResult:
        base_url = self.context.target
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"

        findings = []
        headers = {"User-Agent": "BugFinder/0.1.0"}

        async with httpx.AsyncClient(timeout=30, follow_redirects=True, verify=False) as client:
            try:
                resp = await client.get(base_url, headers=headers)
                content = resp.text.lower()
            except Exception:
                return AgentResult(
                    agent_name=self.name,
                    status="completed",
                    summary="Could not fetch target for XSS scanning",
                )

            import re

            forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', content, re.DOTALL)

            if not forms:
                inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', content)
                if inputs:
                    for inp in inputs:
                        findings.append(
                            {
                                "title": "Form Input Detected (Untested)",
                                "description": (f"Input field '{inp}' found but no form context for automated XSS testing"),
                                "severity": "info",
                                "confidence": "needs_review",
                                "category": "xss",
                                "evidence": {"input_name": inp, "url": base_url},
                            }
                        )
            else:
                test_urls = [base_url]
                for action, _ in forms[:3]:
                    abs_url = urljoin(base_url, action)
                    if abs_url not in test_urls:
                        test_urls.append(abs_url)

                for url in test_urls:
                    parsed = urlparse(url)
                    if parsed.query:
                        params = [p.split("=")[0] for p in parsed.query.split("&") if "=" in p]
                        if not params:
                            continue

                        for payload in XSS_PAYLOADS[:2]:
                            for param in params[:3]:
                                test_url = str(url).replace(f"{param}=", f"{param}={payload}")
                                if test_url == str(url):
                                    test_url = f"{url}&{param}={payload}"
                                try:
                                    test_resp = await client.get(test_url, headers=headers)
                                    if payload.lower() in test_resp.text.lower():
                                        findings.append(
                                            {
                                                "title": "Reflected XSS Detected",
                                                "description": f"Potential XSS in parameter '{param}' at {url}",
                                                "severity": "high",
                                                "confidence": "needs_review",
                                                "category": "xss",
                                                "evidence": {
                                                    "url": test_url,
                                                    "parameter": param,
                                                    "payload": payload,
                                                    "status": test_resp.status_code,
                                                },
                                            }
                                        )
                                except Exception:
                                    continue

        for f in findings:
            f["id"] = f"xss-{findings.index(f)}"

        high_count = sum(1 for f in findings if f["severity"] == "high")
        summary = f"Tested {len(findings)} XSS vectors, {high_count} potential issues"
        return AgentResult(
            agent_name=self.name,
            status="completed",
            findings=findings,
            summary=summary,
        )
