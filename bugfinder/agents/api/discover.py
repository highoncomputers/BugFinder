from __future__ import annotations

from urllib.parse import urljoin, urlparse

import httpx

from bugfinder.agents.base import AgentResult, BaseAgent

API_PATTERNS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/rest",
    "/rest/v1",
    "/graphql",
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/api/docs",
    "/api/swagger",
    "/api/documentation",
    "/v1",
    "/v2",
    "/api/health",
    "/api/status",
    "/api/version",
    "/api/users",
    "/api/auth",
    "/api/login",
    "/api/data",
    "/api/config",
]


class APIDiscoverAgent(BaseAgent):
    name = "api.discover"
    description = "API endpoint discovery"

    async def execute(self) -> AgentResult:
        base_url = self.context.target
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"
        base_url = base_url.rstrip("/")

        headers = {"User-Agent": "BugFinder/0.1.0", "Accept": "application/json"}
        findings = []
        assets = []

        async with httpx.AsyncClient(timeout=30, follow_redirects=True, verify=False) as client:
            for path in API_PATTERNS:
                url = urljoin(base_url, path)
                parsed = urlparse(url)
                if parsed.path == "/":
                    continue
                try:
                    resp = await client.get(url, headers=headers)
                    is_json = "application/json" in resp.headers.get("content-type", "")
                    path.endswith((".yaml", ".yml"))

                    if resp.status_code < 500:
                        asset = {
                            "id": f"api-{path.replace('/', '_')}",
                            "name": url,
                            "asset_type": "api_route",
                            "value": f"HTTP {resp.status_code}",
                            "properties": {
                                "path": path,
                                "status": resp.status_code,
                                "json_response": is_json,
                            },
                        }
                        assets.append(asset)

                        if is_json and resp.status_code == 200:
                            if path in ("/openapi.json", "/swagger.json"):
                                findings.append(
                                    {
                                        "title": "OpenAPI/Swagger Specification Found",
                                        "description": f"API specification exposed at {url}. "
                                        "This helps map the full API attack surface.",
                                        "severity": "info",
                                        "confidence": "verified",
                                        "category": "api_discovery",
                                        "evidence": {
                                            "url": url,
                                            "has_spec": True,
                                            "status": resp.status_code,
                                        },
                                    }
                                )
                            elif resp.status_code == 200:
                                findings.append(
                                    {
                                        "title": f"API Endpoint Discovered: {path}",
                                        "description": f"API endpoint accessible at {url} (HTTP {resp.status_code})",
                                        "severity": "info",
                                        "category": "api_discovery",
                                        "evidence": {
                                            "url": url,
                                            "path": path,
                                            "status": resp.status_code,
                                        },
                                    }
                                )

                        if resp.status_code == 401 or resp.status_code == 403:
                            findings.append(
                                {
                                    "title": f"API Authentication Required: {path}",
                                    "description": (
                                        f"API endpoint {url} requires authentication (HTTP {resp.status_code})"
                                    ),
                                    "severity": "info",
                                    "category": "authentication",
                                    "evidence": {
                                        "url": url,
                                        "path": path,
                                        "status": resp.status_code,
                                    },
                                }
                            )

                except Exception:
                    continue

        for f in findings:
            f["id"] = f"api-disc-{findings.index(f)}"

        discovered = len(assets)
        secured = sum(1 for a in assets if a["properties"]["status"] in (401, 403))
        summary = f"Discovered {discovered} API endpoints, {secured} authenticated"
        return AgentResult(
            agent_name=self.name,
            status="completed",
            assets=assets,
            findings=findings,
            summary=summary,
        )
