from __future__ import annotations

from bugfinder.core.types import TargetType
from bugfinder.workflow import Phase


class PhaseDefinitions:
    def get_agents_for_phase(self, phase: Phase, target_type: TargetType, profile: str = "quick") -> list[str]:
        phase_map = {
            Phase.RECON: self._recon_agents,
            Phase.VULN_DETECTION: self._vuln_agents,
            Phase.EXPLOITATION: self._exploit_agents,
            Phase.REPORTING: self._reporting_agents,
        }
        getter = phase_map.get(phase)
        if getter:
            return getter(target_type, profile)
        return []

    def _recon_agents(self, target_type: TargetType, profile: str) -> list[str]:
        base = ["dns", "tech", "port"]
        if target_type in (TargetType.WEBSITE, TargetType.API, TargetType.DOMAIN, TargetType.URL):
            base.extend(["cert", "wayback", "googledorks"])
        if profile != "quick":
            base.append("service")
            base.append("crawler")
        if profile == "deep":
            base.append("github")
        return base

    def _vuln_agents(self, target_type: TargetType, profile: str) -> list[str]:
        base = ["xss", "sqli", "ssti", "lfi", "ssrf"]
        if target_type in (TargetType.WEBSITE, TargetType.URL):
            base.extend(["cookies", "csp", "cors", "jwt", "csrf", "redirect", "host_header", "cache", "graphql"])
            base.extend(["auth", "js"])
            if profile != "quick":
                base.extend(["race", "xxe"])
        if target_type == TargetType.API:
            base.extend(["graphql", "jwt", "cors", "rate"])
            base.extend(["discover", "fuzz"])
        if target_type == TargetType.ANDROID:
            base.extend(["decompile", "webview", "storage", "deeplinks"])
        if profile == "deep":
            base.extend(["cloud", "s3", "gcp", "azure", "firebase", "secrets", "tls"])
        return base

    def _exploit_agents(self, target_type: TargetType, profile: str) -> list[str]:
        return ["verify"]

    def _reporting_agents(self, target_type: TargetType, profile: str) -> list[str]:
        return ["correlation"]
