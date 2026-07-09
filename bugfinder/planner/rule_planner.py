from __future__ import annotations

from bugfinder.core.types import TargetType
from bugfinder.planner.base import BasePlanner
from bugfinder.planner.plan import AssessmentPlan, PlanStep

TARGET_PLANS: dict[TargetType, list[dict]] = {
    TargetType.WEBSITE: [
        {"agent": "recon.dns", "rationale": "Discover DNS records and subdomains"},
        {"agent": "recon.tech", "rationale": "Identify web technologies and frameworks"},
        {"agent": "recon.wayback", "rationale": "Check historical endpoints via Wayback Machine"},
        {"agent": "web.crawler", "rationale": "Map application pages and endpoints"},
        {"agent": "web.js", "rationale": "Analyze JavaScript for secrets and API routes"},
        {"agent": "web.auth", "rationale": "Find and analyze authentication mechanisms"},
        {"agent": "api.discover", "rationale": "Discover API endpoints from the application"},
        {"agent": "cloud.detect", "rationale": "Detect cloud providers and resources"},
        {"agent": "web.xss", "rationale": "Test for Cross-Site Scripting vulnerabilities"},
        {"agent": "web.sqli", "rationale": "Test for SQL injection vulnerabilities"},
        {"agent": "web.ssti", "rationale": "Test for Server-Side Template Injection"},
        {"agent": "web.ssrf", "rationale": "Test for Server-Side Request Forgery"},
        {"agent": "web.lfi", "rationale": "Test for Local File Inclusion"},
        {"agent": "web.graphql", "rationale": "Test GraphQL endpoints for vulnerabilities"},
        {"agent": "web.jwt", "rationale": "Analyze JWT tokens for weaknesses"},
        {"agent": "web.cors", "rationale": "Test for CORS misconfigurations"},
        {"agent": "web.cookies", "rationale": "Check cookie security flags"},
        {"agent": "web.csp", "rationale": "Analyze Content Security Policy"},
        {"agent": "web.csrf", "rationale": "Test for Cross-Site Request Forgery"},
        {"agent": "web.redirect", "rationale": "Test for open redirect vulnerabilities"},
        {"agent": "web.host_header", "rationale": "Test for Host header injection"},
        {"agent": "web.cache", "rationale": "Check for cache poisoning opportunities"},
        {"agent": "secrets.scan", "rationale": "Scan for exposed secrets and credentials"},
        {"agent": "correlation", "rationale": "Correlate findings and detect attack chains"},
        {"agent": "verification", "rationale": "Verify discovered findings"},
    ],
    TargetType.API: [
        {"agent": "api.discover", "rationale": "Discover API endpoints and parameters"},
        {"agent": "recon.tech", "rationale": "Identify API framework and technologies"},
        {"agent": "web.auth", "rationale": "Test authentication and authorization"},
        {"agent": "web.jwt", "rationale": "Analyze JWT authentication tokens"},
        {"agent": "web.cors", "rationale": "Test API CORS configuration"},
        {"agent": "web.graphql", "rationale": "Test GraphQL introspection and batching"},
        {"agent": "web.xss", "rationale": "Test API endpoints for XSS"},
        {"agent": "web.sqli", "rationale": "Test API parameters for injection"},
        {"agent": "api.fuzz", "rationale": "Fuzz API endpoints for hidden parameters"},
        {"agent": "api.rate", "rationale": "Test API rate limiting"},
        {"agent": "secrets.scan", "rationale": "Scan for exposed secrets in responses"},
        {"agent": "correlation", "rationale": "Correlate findings"},
        {"agent": "verification", "rationale": "Verify discovered findings"},
    ],
    TargetType.ANDROID: [
        {"agent": "android.decompile", "rationale": "Decompile APK for analysis"},
        {"agent": "android.webview", "rationale": "Check WebView security configuration"},
        {"agent": "android.storage", "rationale": "Check local storage security"},
        {"agent": "android.deeplinks", "rationale": "Analyze deep link handlers"},
        {"agent": "secrets.scan", "rationale": "Scan decompiled code for secrets"},
        {"agent": "correlation", "rationale": "Correlate findings"},
        {"agent": "verification", "rationale": "Verify discovered findings"},
    ],
    TargetType.DOMAIN: [
        {"agent": "recon.dns", "rationale": "Discover DNS records and subdomains"},
        {"agent": "recon.tech", "rationale": "Identify web technologies"},
        {"agent": "recon.wayback", "rationale": "Check historical endpoints"},
        {"agent": "recon.github", "rationale": "Search GitHub for exposed data"},
        {"agent": "recon.googledorks", "rationale": "Generate Google dork queries"},
        {"agent": "web.crawler", "rationale": "Map application pages"},
        {"agent": "cloud.detect", "rationale": "Detect cloud providers"},
        {"agent": "cloud.s3", "rationale": "Check for S3 buckets"},
        {"agent": "cloud.gcp", "rationale": "Check for GCP storage"},
        {"agent": "cloud.azure", "rationale": "Check for Azure storage"},
        {"agent": "cloud.firebase", "rationale": "Check for Firebase databases"},
        {"agent": "infra.port", "rationale": "Scan for open ports"},
        {"agent": "infra.tls", "rationale": "Check TLS configuration"},
        {"agent": "web.js", "rationale": "Analyze JavaScript"},
        {"agent": "secrets.scan", "rationale": "Scan for secrets"},
        {"agent": "correlation", "rationale": "Correlate findings"},
        {"agent": "verification", "rationale": "Verify discoveries"},
    ],
    TargetType.CIDR: [
        {"agent": "infra.port", "rationale": "Scan for open ports on targets"},
        {"agent": "infra.service", "rationale": "Identify running services"},
        {"agent": "infra.tls", "rationale": "Check TLS on HTTPS ports"},
        {"agent": "recon.dns", "rationale": "Reverse DNS lookups"},
        {"agent": "verification", "rationale": "Verify discoveries"},
    ],
    TargetType.IP_ADDRESS: [
        {"agent": "infra.port", "rationale": "Scan for open ports"},
        {"agent": "infra.service", "rationale": "Identify running services"},
        {"agent": "infra.tls", "rationale": "Check TLS on HTTPS ports"},
        {"agent": "recon.dns", "rationale": "Reverse DNS lookup"},
        {"agent": "verification", "rationale": "Verify discoveries"},
    ],
    TargetType.ANDROID: [
        {"agent": "android.decompile", "rationale": "Decompile APK for analysis"},
        {"agent": "android.webview", "rationale": "Check WebView security configuration"},
        {"agent": "android.storage", "rationale": "Check local storage security"},
        {"agent": "android.deeplinks", "rationale": "Analyze deep link handlers"},
        {"agent": "secrets.scan", "rationale": "Scan decompiled code for secrets"},
        {"agent": "correlation", "rationale": "Correlate findings"},
        {"agent": "verification", "rationale": "Verify discovered findings"},
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
        {"agent": "web.xss", "rationale": "Basic XSS check"},
        {"agent": "web.sqli", "rationale": "Basic SQLi check"},
    ],
    "deep": None,
    "stealth": [
        {"agent": "recon.dns", "rationale": "Passive DNS recon"},
        {"agent": "recon.cert", "rationale": "Certificate transparency"},
        {"agent": "recon.tech", "rationale": "Passive technology detection"},
    ],
}
