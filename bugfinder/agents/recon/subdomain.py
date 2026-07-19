from __future__ import annotations

from bugfinder.agents.base import AgentContext, AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity
from bugfinder.utils.http import get


class SubdomainAgent(BaseAgent):
    category = "recon"
    name = "subdomain"

    async def execute(self, context: AgentContext) -> AgentResult:
        findings = []
        target = context.target
        domain = target.hostname

        common_subdomains = [
            "www",
            "mail",
            "remote",
            "blog",
            "webmail",
            "server",
            "ns1",
            "ns2",
            "smtp",
            "secure",
            "vpn",
            "admin",
            "cpanel",
            "whm",
            "dev",
            "test",
            "staging",
            "api",
            "app",
            "m",
            "mobile",
            "shop",
            "store",
            "portal",
            "cdn",
            "static",
            "assets",
            "img",
            "docs",
            "help",
            "support",
            "status",
        ]

        found_subdomains = []
        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                resp = await get(f"http://{subdomain}", timeout=5)
                if hasattr(resp, "status_code") and resp.status_code < 400:
                    found_subdomains.append(subdomain)
            except Exception:
                pass

        if found_subdomains:
            findings.append(
                {
                    "title": "Subdomains Discovered",
                    "description": f"Discovered {len(found_subdomains)} subdomains for {domain}.",
                    "severity": Severity.INFO,
                    "confidence": Confidence.MEDIUM,
                    "category": "recon",
                    "cwe_id": "200",
                    "owasp_category": "A01-Broken Access Control",
                    "cvss_score": 0.0,
                    "evidence": {"domain": domain, "subdomains_found": found_subdomains, "total_checked": len(common_subdomains)},
                    "remediation": "Ensure subdomains don't expose staging or test environments. Audit subdomain DNS records.",
                }
            )

        return AgentResult(
            agent_name="subdomain",
            status="completed",
            findings=findings,
            summary=f"Found {len(found_subdomains)} subdomains",
        )
