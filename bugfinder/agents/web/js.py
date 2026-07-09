from __future__ import annotations

import re
from urllib.parse import urljoin

import httpx

from bugfinder.agents.base import AgentResult, BaseAgent

API_ROUTE_PATTERNS = re.compile(
    r'(?:"|\\x27)(?:/(?:api|v[12]|rest|graphql)[a-zA-Z0-9_/.-]*)(?:"|\\x27)',
    re.IGNORECASE,
)
SECRET_PATTERNS_RE = re.compile(
    r"(?:sk-[A-Za-z0-9]{32,}|gh[ps]_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16})",
)
ENDPOINT_PATTERNS = re.compile(
    r'(?:fetch|axios|ajax|XMLHttpRequest|fetchApi|\.get|\.post|\.put|\.delete)\s*\(\s*["\']([^"\']+)["\']',
)


class JSAnalyzerAgent(BaseAgent):
    name = "web.js"
    description = "JavaScript analysis for secrets and API routes"

    async def execute(self) -> AgentResult:
        base_url = self.context.target
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"

        findings = []
        assets = []
        headers = {"User-Agent": "BugFinder/0.1.0"}

        async with httpx.AsyncClient(timeout=30, follow_redirects=True, verify=False) as client:
            try:
                resp = await client.get(base_url, headers=headers)
                html = resp.text
            except Exception:
                return AgentResult(
                    agent_name=self.name,
                    status="completed",
                    summary="Could not fetch target for JS analysis",
                )

            script_srcs = re.findall(r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE)
            inline_scripts = re.findall(r"<script[^>]*>(.*?)</script>", html, re.DOTALL)

            js_urls = set()
            for src in script_srcs[:30]:
                js_url = urljoin(base_url, src)
                js_urls.add(js_url)

            for js_url in js_urls:
                try:
                    js_resp = await client.get(js_url, headers=headers)
                    js_content = js_resp.text

                    api_routes = set(API_ROUTE_PATTERNS.findall(js_content))
                    for route in api_routes:
                        clean = route.strip('"').strip("'")
                        if len(clean) > 3:
                            assets.append(
                                {
                                    "id": f"js-api-{hash(clean) & 0xFFFFFFFF}",
                                    "name": clean,
                                    "asset_type": "api_route",
                                    "value": f"Found in {js_url.rsplit('/', 1)[-1]}",
                                    "properties": {"source": js_url, "route": clean},
                                }
                            )

                    secrets = set(SECRET_PATTERNS_RE.findall(js_content))
                    for secret in secrets:
                        findings.append(
                            {
                                "title": "Potential Secret in JavaScript",
                                "description": f"Secret-like string found in {js_url}",
                                "severity": "critical",
                                "confidence": "needs_review",
                                "category": "secret_exposure",
                                "evidence": {
                                    "url": js_url,
                                    "secret_prefix": secret[:20],
                                },
                            }
                        )

                    endpoints = set(ENDPOINT_PATTERNS.findall(js_content))
                    for ep in endpoints:
                        if ep not in api_routes and len(ep) > 5:
                            assets.append(
                                {
                                    "id": f"js-ep-{hash(ep) & 0xFFFFFFFF}",
                                    "name": ep,
                                    "asset_type": "api_route",
                                    "value": f"JS endpoint in {js_url.rsplit('/', 1)[-1]}",
                                    "properties": {"source": js_url, "route": ep},
                                }
                            )

                except Exception:
                    continue

            for i, inline in enumerate(inline_scripts[:5]):
                secrets = set(SECRET_PATTERNS_RE.findall(inline))
                for secret in secrets:
                    findings.append(
                        {
                            "title": "Potential Secret in Inline Script",
                            "description": "Secret-like string found in inline JavaScript",
                            "severity": "critical",
                            "confidence": "needs_review",
                            "category": "secret_exposure",
                            "evidence": {"url": base_url, "secret_prefix": secret[:20]},
                        }
                    )

        for f in findings:
            f["id"] = f"js-finding-{findings.index(f)}"
        api_count = sum(1 for a in assets if a["asset_type"] == "api_route")
        summary = f"Analyzed {len(js_urls)} JS files, found {api_count} API routes, {len(findings)} secrets"
        return AgentResult(
            agent_name=self.name,
            status="completed",
            assets=assets,
            findings=findings,
            summary=summary,
        )
