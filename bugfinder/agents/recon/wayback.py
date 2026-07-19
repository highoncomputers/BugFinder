from __future__ import annotations

from bugfinder.agents.base import AgentContext, AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity
from bugfinder.utils.http import get


class WaybackAgent(BaseAgent):
    category = "recon"
    name = "wayback"

    async def execute(self, context: AgentContext) -> AgentResult:
        findings = []
        target = context.target
        domain = target.hostname

        cdx_url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=500&fl=original,timestamp,statuscode"

        try:
            resp = await get(cdx_url, timeout=30)
            if hasattr(resp, "status_code") and resp.status_code == 200:
                data = resp.json() if hasattr(resp, "json") else []
                if len(data) > 1:
                    urls = [row[0] for row in data[1:] if row and len(row) > 0]

                    unique_urls = list(set(urls))[:200]
                    interesting = [
                        u
                        for u in unique_urls
                        if any(
                            ext in u.lower()
                            for ext in [
                                ".git",
                                ".env",
                                "admin",
                                "api",
                                "backup",
                                "config",
                                "db",
                                "sql",
                                "dump",
                                "password",
                                "secret",
                                "token",
                                "key",
                                "aws",
                                "s3",
                                "debug",
                                "test",
                                "staging",
                                "dev",
                                "internal",
                                "swagger",
                                "graphql",
                                "wp-",
                                "phpinfo",
                            ]
                        )
                    ]

                    findings.append(
                        {
                            "title": "Historical URLs Discovered via Wayback Machine",
                            "description": f"Found {len(unique_urls)} unique historical URLs for {domain}.",
                            "severity": Severity.INFO,
                            "confidence": Confidence.HIGH,
                            "category": "recon",
                            "cwe_id": "200",
                            "owasp_category": "A01-Broken Access Control",
                            "cvss_score": 0.0,
                            "evidence": {
                                "domain": domain,
                                "total_urls": len(urls),
                                "unique_urls": len(unique_urls),
                                "sample_urls": unique_urls[:20],
                                "interesting_endpoints": interesting[:10],
                            },
                            "remediation": "Review historical endpoints for exposed sensitive information. Use robots.txt to control crawling.",
                        }
                    )
        except Exception:
            pass

        return AgentResult(
            agent_name="wayback",
            status="completed",
            findings=findings,
            summary=f"Wayback recon completed for {domain}",
        )
