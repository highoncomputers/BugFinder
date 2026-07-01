from __future__ import annotations

from urllib.parse import urlparse

from bugfinder.core.config import settings
from bugfinder.core.exceptions import ScopeViolationError


class ScopeEnforcer:
    def __init__(self, allowed_domains: list[str] | None = None) -> None:
        self.allowed_domains = allowed_domains or settings.allowed_domains
        self.enabled = settings.scope_enforcement

    def check_url(self, url: str) -> None:
        if not self.enabled or not self.allowed_domains:
            return
        hostname = urlparse(url).hostname
        if hostname is None:
            return
        hostname = hostname.lower()
        for domain in self.allowed_domains:
            domain = domain.lower()
            if hostname == domain or hostname.endswith(f".{domain}"):
                return
            if domain.startswith("*."):
                base = domain[2:]
                if hostname.endswith(f".{base}") or hostname == base:
                    return
        raise ScopeViolationError(f"URL {url} is outside authorized scope")

    def check_hostname(self, hostname: str) -> None:
        if not self.enabled or not self.allowed_domains:
            return
        hostname = hostname.lower()
        for domain in self.allowed_domains:
            domain = domain.lower()
            if hostname == domain or hostname.endswith(f".{domain}"):
                return
        raise ScopeViolationError(f"Hostname {hostname} is outside authorized scope")
