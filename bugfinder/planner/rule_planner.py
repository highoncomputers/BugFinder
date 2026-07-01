from __future__ import annotations

from bugfinder.core.types import TargetType
from bugfinder.planner.base import BasePlanner
from bugfinder.planner.plan import AssessmentPlan, PlanStep

TARGET_PLANS: dict[TargetType, list[dict]] = {
    TargetType.WEBSITE: [
        {"agent": "recon.dns", "rationale": "Discover DNS records and subdomains"},
        {"agent": "recon.tech", "rationale": "Identify web technologies and frameworks"},
        {"agent": "web.crawler", "rationale": "Map application pages and endpoints"},
        {"agent": "web.js", "rationale": "Analyze JavaScript for secrets and API routes"},
        {"agent": "web.auth", "rationale": "Find and analyze authentication mechanisms"},
        {"agent": "api.discover", "rationale": "Discover API endpoints from the application"},
        {"agent": "web.xss", "rationale": "Test for Cross-Site Scripting vulnerabilities"},
        {"agent": "web.sqli", "rationale": "Test for SQL injection vulnerabilities"},
        {"agent": "web.ssrf", "rationale": "Test for Server-Side Request Forgery"},
        {"agent": "web.lfi", "rationale": "Test for Local File Inclusion"},
        {"agent": "secrets.scan", "rationale": "Scan for exposed secrets and credentials"},
        {"agent": "verification", "rationale": "Verify discovered findings"},
    ],
    TargetType.API: [
        {"agent": "api.discover", "rationale": "Discover API endpoints and parameters"},
        {"agent": "recon.tech", "rationale": "Identify API framework and technologies"},
        {"agent": "api.auth", "rationale": "Test authentication and authorization"},
        {"agent": "api.fuzz", "rationale": "Fuzz API parameters for injection flaws"},
        {"agent": "api.rate", "rationale": "Test rate limiting and abuse controls"},
        {"agent": "secrets.scan", "rationale": "Scan for exposed secrets in responses"},
        {"agent": "verification", "rationale": "Verify discovered findings"},
    ],
    TargetType.ANDROID: [
        {"agent": "android.decompile", "rationale": "Decompile APK for analysis"},
        {"agent": "android.manifest", "rationale": "Analyze AndroidManifest.xml"},
        {"agent": "secrets.scan", "rationale": "Scan decompiled code for secrets"},
        {"agent": "android.web", "rationale": "Check WebView configurations"},
        {"agent": "verification", "rationale": "Verify discovered findings"},
    ],
    TargetType.DOMAIN: [
        {"agent": "recon.dns", "rationale": "Discover DNS records and subdomains"},
        {"agent": "recon.whois", "rationale": "Gather WHOIS information"},
        {"agent": "recon.cert", "rationale": "Check certificate transparency logs"},
        {"agent": "recon.tech", "rationale": "Identify web technologies"},
        {"agent": "web.crawler", "rationale": "Map application pages"},
        {"agent": "verification", "rationale": "Verify discoveries"},
    ],
    TargetType.CIDR: [
        {"agent": "infra.port", "rationale": "Scan for open ports on targets"},
        {"agent": "infra.service", "rationale": "Identify running services"},
        {"agent": "recon.dns", "rationale": "Reverse DNS lookups"},
        {"agent": "verification", "rationale": "Verify discoveries"},
    ],
    TargetType.IP_ADDRESS: [
        {"agent": "infra.port", "rationale": "Scan for open ports"},
        {"agent": "infra.service", "rationale": "Identify running services"},
        {"agent": "recon.dns", "rationale": "Reverse DNS lookup"},
        {"agent": "verification", "rationale": "Verify discoveries"},
    ],
}


class RulePlanner(BasePlanner):
    async def create_plan(self, target: str, target_type: str) -> AssessmentPlan:
        plan = AssessmentPlan(target=target, target_type=target_type)
        try:
            tt = TargetType(target_type)
        except ValueError:
            tt = TargetType.UNKNOWN

        steps = TARGET_PLANS.get(tt, [])
        for i, step_def in enumerate(steps):
            step = PlanStep(
                agent_name=step_def["agent"],
                priority=i,
                rationale=step_def["rationale"],
            )
            plan.add_step(step)
        return plan


PLANNER_STRATEGIES: dict[str, list[dict]] = {
    "quick": [
        {"agent": "recon.dns", "rationale": "Quick DNS check"},
        {"agent": "recon.tech", "rationale": "Technology identification"},
        {"agent": "web.crawler", "rationale": "Fast crawl"},
    ],
    "deep": None,  # Use full TARGET_PLANS
    "stealth": [
        {"agent": "recon.dns", "rationale": "Passive DNS recon"},
        {"agent": "recon.cert", "rationale": "Certificate transparency"},
        {"agent": "recon.tech", "rationale": "Passive technology detection"},
    ],
}
