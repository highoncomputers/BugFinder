from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from bugfinder.core.types import TargetType


@dataclass
class WorkflowTemplate:
    name: str
    description: str
    target_types: list[TargetType]
    agents: list[str]
    phases: list[str]


WORKFLOW_TEMPLATES: dict[str, WorkflowTemplate] = {
    "bug-bounty-standard": WorkflowTemplate(
        name="Bug Bounty Standard",
        description="Standard bug bounty workflow: recon, web vuln scan, exploit, report",
        target_types=[TargetType.WEBSITE, TargetType.URL, TargetType.DOMAIN, TargetType.API],
        agents=["dns", "tech", "port", "cert", "crawler", "xss", "sqli", "ssti", "lfi", "ssrf",
                "cookies", "csp", "cors", "jwt", "redirect", "host_header", "correlation"],
        phases=["recon", "vuln_detection", "exploitation", "reporting"],
    ),
    "quick-win": WorkflowTemplate(
        name="Quick Win",
        description="Rapid scan for low-hanging fruit: secrets, basic web vulns, misconfigs",
        target_types=[TargetType.WEBSITE, TargetType.URL, TargetType.API],
        agents=["tech", "xss", "sqli", "secrets", "cors", "cookies"],
        phases=["recon", "vuln_detection", "reporting"],
    ),
    "deep-dive": WorkflowTemplate(
        name="Deep Dive",
        description="Maximum coverage: all agents, cloud checks, race conditions, Android analysis",
        target_types=[TargetType.WEBSITE, TargetType.API, TargetType.APK, TargetType.IP, TargetType.CIDR],
        agents=["dns", "tech", "port", "cert", "service", "crawler", "wayback", "github", "googledorks",
                "xss", "sqli", "ssti", "xxe", "lfi", "ssrf", "graphql", "jwt", "cors", "cookies",
                "csrf", "redirect", "host_header", "race", "cache", "secrets", "tls",
                "s3", "gcp", "azure", "firebase", "decompile", "verification", "correlation"],
        phases=["recon", "vuln_detection", "exploitation", "reporting"],
    ),
    "compliance": WorkflowTemplate(
        name="Compliance Scan",
        description="Security headers, cookie flags, TLS, CSP, CORS verification for compliance",
        target_types=[TargetType.WEBSITE, TargetType.URL],
        agents=["tech", "cookies", "csp", "cors", "tls", "auth", "secrets"],
        phases=["recon", "vuln_detection", "reporting"],
    ),
    "android-security": WorkflowTemplate(
        name="Android Security",
        description="Full Android APK security analysis",
        target_types=[TargetType.APK],
        agents=["decompile", "webview", "storage", "deeplinks", "secrets"],
        phases=["recon", "vuln_detection", "reporting"],
    ),
    "cloud-review": WorkflowTemplate(
        name="Cloud Security Review",
        description="Cloud infrastructure security assessment",
        target_types=[TargetType.WEBSITE, TargetType.DOMAIN],
        agents=["tech", "s3", "gcp", "azure", "firebase", "secrets", "csp", "tls"],
        phases=["recon", "vuln_detection", "reporting"],
    ),
}


def get_template(name: str) -> Optional[WorkflowTemplate]:
    return WORKFLOW_TEMPLATES.get(name)


def list_templates() -> list[dict[str, str]]:
    return [
        {"name": t.name, "description": t.description}
        for t in WORKFLOW_TEMPLATES.values()
    ]
