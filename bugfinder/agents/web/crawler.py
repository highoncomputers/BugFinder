from __future__ import annotations

from urllib.parse import urljoin

import httpx

from bugfinder.agents.base import AgentResult, BaseAgent

COMMON_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/admin",
    "/login",
    "/wp-admin",
    "/administrator",
    "/api",
    "/v1",
    "/v2",
    "/api/v1",
    "/api/v2",
    "/graphql",
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/.env",
    "/config",
    "/backup",
    "/.git/config",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
]


class CrawlerAgent(BaseAgent):
    name = "web.crawler"
    description = "Web application crawler and directory enumeration"

    async def execute(self) -> AgentResult:
        base_url = self.context.target
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"
        base_url = base_url.rstrip("/")

        headers = {"User-Agent": "BugFinder/0.1.0"}
        findings = []
        assets = []

        async with httpx.AsyncClient(timeout=30, follow_redirects=True, verify=False) as client:
            try:
                resp = await client.get(base_url, headers=headers)
                assets.append(
                    {
                        "id": "page-index",
                        "name": base_url,
                        "asset_type": "endpoint",
                        "value": f"HTTP {resp.status_code} ({len(resp.content)} bytes)",
                        "properties": {"status": resp.status_code, "size": len(resp.content)},
                    }
                )
                if resp.status_code == 401:
                    findings.append(
                        {
                            "title": "Authentication Required on Landing Page",
                            "description": f"{base_url} returns 401 Unauthorized",
                            "severity": "info",
                            "category": "authentication",
                            "evidence": {"url": base_url, "status": 401},
                        }
                    )
            except Exception as e:
                return AgentResult(
                    agent_name=self.name,
                    status="completed",
                    summary=f"Crawl failed: {e}",
                )

            discovered_assets = []
            for path in COMMON_PATHS:
                url = urljoin(base_url, path)
                try:
                    resp = await client.get(url, headers=headers)
                    asset_id = f"page-{path.replace('/', '_')}"
                    asset = {
                        "id": asset_id,
                        "name": url,
                        "asset_type": "endpoint",
                        "value": f"HTTP {resp.status_code}",
                        "properties": {
                            "status": resp.status_code,
                            "path": path,
                            "size": len(resp.content),
                        },
                    }
                    discovered_assets.append(asset)
                    assets.append(asset)

                    if resp.status_code == 200:
                        if path == "/robots.txt":
                            findings.append(
                                {
                                    "title": "Robots.txt Discovered",
                                    "description": f"Robots.txt found at {url}",
                                    "severity": "info",
                                    "category": "information_disclosure",
                                    "evidence": {"url": url, "content": resp.text[:500]},
                                }
                            )
                        elif "admin" in path.lower() or "login" in path.lower():
                            findings.append(
                                {
                                    "title": f"Admin/Login Page Found: {path}",
                                    "description": f"Protected page accessible at {url}",
                                    "severity": "medium" if resp.status_code == 200 else "info",
                                    "category": "exposed_endpoint",
                                    "evidence": {"url": url, "status": resp.status_code},
                                }
                            )
                        elif ".git" in path:
                            findings.append(
                                {
                                    "title": "Exposed .git Directory",
                                    "description": f".git directory exposed at {url}",
                                    "severity": "high",
                                    "category": "information_disclosure",
                                    "evidence": {"url": url},
                                }
                            )
                        elif ".env" in path:
                            findings.append(
                                {
                                    "title": "Exposed .env File",
                                    "description": f"Environment file exposed at {url}",
                                    "severity": "critical",
                                    "category": "secret_exposure",
                                    "evidence": {"url": url},
                                }
                            )
                except Exception:
                    continue

        for f in findings:
            f["id"] = f"crawl-finding-{findings.index(f)}"

        statuses = [a["properties"]["status"] for a in discovered_assets]
        accessible = sum(1 for s in statuses if s < 400)
        summary = f"Crawled {len(discovered_assets) + 1} paths, {accessible} accessible, {len(findings)} findings"

        return AgentResult(
            agent_name=self.name,
            status="completed",
            assets=assets,
            findings=findings,
            summary=summary,
        )
