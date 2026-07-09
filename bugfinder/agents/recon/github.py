from __future__ import annotations

from typing import Any

from bugfinder.agents.base import BaseAgent, AgentContext, AgentResult
from bugfinder.core.types import Severity, Confidence
from bugfinder.utils.http import get


class GitHubAgent(BaseAgent):
    category = "recon"
    name = "github"

    async def execute(self, context: AgentContext) -> AgentResult:
        findings = []
        target = context.target
        domain = target.hostname

        from bugfinder.core.config import Settings
        settings = Settings()
        gh_token = getattr(settings, "github_token", "") or ""

        dorks = [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret',
            f'"{domain}" token',
            f'"{domain}" aws_key',
            f'"{domain}" .env',
            f'"{domain}" database',
            f'"{domain}" config',
        ]

        headers = {"Accept": "application/vnd.github.v3+json"}
        if gh_token:
            headers["Authorization"] = f"token {gh_token}"

        all_results = []
        for dork in dorks[:3]:
            try:
                search_url = f"https://api.github.com/search/code?q={dork}&per_page=5"
                resp = await get(search_url, headers=headers, timeout=15)
                if hasattr(resp, 'status_code') and resp.status_code == 200:
                    data = resp.json() if hasattr(resp, 'json') else {}
                    items = data.get("items", [])
                    for item in items:
                        all_results.append({
                            "repo": item.get("repository", {}).get("full_name", "unknown"),
                            "path": item.get("path", "unknown"),
                            "url": item.get("html_url", ""),
                        })
            except Exception:
                pass

        if all_results:
            findings.append({
                "title": "GitHub Code Search Results",
                "description": f"Found {len(all_results)} potential secrets/references for {domain} on GitHub.",
                "severity": Severity.MEDIUM,
                "confidence": Confidence.MEDIUM,
                "category": "recon",
                "cwe_id": "200",
                "owasp_category": "A05-Security Misconfiguration",
                "cvss_score": 5.0,
                "evidence": {"domain": domain, "results": all_results[:10], "searches": dorks[:3]},
                "remediation": "Use .gitignore for sensitive files. Regularly audit GitHub for exposed data.",
            })

        return AgentResult(
            agent_name="github",
            status="completed",
            findings=findings,
            summary=f"GitHub recon found {len(all_results)} results",
        )
