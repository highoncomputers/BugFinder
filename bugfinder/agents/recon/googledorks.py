from __future__ import annotations

from bugfinder.agents.base import AgentContext, AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity


class GoogleDorkAgent(BaseAgent):
    category = "recon"
    name = "googledorks"

    async def execute(self, context: AgentContext) -> AgentResult:
        findings = []
        target = context.target
        domain = target.hostname

        dorks = [
            {"query": f"site:{domain} intitle:index.of", "description": "Directory listing"},
            {"query": f"site:{domain} inurl:admin", "description": "Admin panels"},
            {"query": f"site:{domain} ext:sql", "description": "SQL files"},
            {"query": f"site:{domain} ext:env", "description": "Environment files"},
            {"query": f"site:{domain} ext:log", "description": "Log files"},
            {"query": f"site:{domain} ext:bak OR ext:backup OR ext:old", "description": "Backup files"},
            {"query": f"site:{domain} inurl:phpinfo.php", "description": "PHP info"},
            {"query": f"site:{domain} inurl:wp-content", "description": "WordPress content"},
            {"query": f"site:{domain} intext:password", "description": "Password disclosure"},
            {"query": f"site:{domain} inurl:api", "description": "API endpoints"},
            {"query": f"site:{domain} inurl:.git", "description": "Git exposure"},
            {"query": f"site:{domain} inurl:debug", "description": "Debug pages"},
            {"query": f"site:{domain} inurl:test OR inurl:staging", "description": "Test environments"},
            {"query": f"site:{domain} filetype:pdf confidential", "description": "Confidential PDFs"},
            {"query": f'site:{domain} "s3.amazonaws.com"', "description": "S3 buckets"},
            {"query": f'site:github.com "{domain}" password', "description": "GitHub password leaks"},
            {"query": f'site:pastebin.com "{domain}"', "description": "Pastebin mentions"},
        ]

        findings.append(
            {
                "title": "Google Dorks Generated",
                "description": f"Generated {len(dorks)} Google dork queries for {domain}. Run these manually via Google Search.",
                "severity": Severity.INFO,
                "confidence": Confidence.HIGH,
                "category": "recon",
                "cwe_id": "200",
                "owasp_category": "A01-Broken Access Control",
                "cvss_score": 0.0,
                "evidence": {
                    "domain": domain,
                    "dorks": dorks,
                    "manual_search_urls": [
                        f"https://www.google.com/search?q={dork['query'].replace(':', '%3A').replace(' ', '+')}"
                        for dork in dorks[:5]
                    ],
                },
                "remediation": "Regularly monitor Google dork results. Remove exposed sensitive information.",
            }
        )

        return AgentResult(
            agent_name="googledorks",
            status="completed",
            findings=findings,
            summary=f"Generated {len(dorks)} Google dorks for {domain}",
        )
