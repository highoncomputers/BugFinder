from __future__ import annotations

from urllib.parse import urlparse

from bugfinder.core.exceptions import ScopeViolationError
from bugfinder.core.config import settings


class ScopeValidator:
    def __init__(self, allowed_domains: list[str] | None = None) -> None:
        self.allowed_domains = allowed_domains or settings.allowed_domains
        self.enforcement = settings.scope_enforcement

    def validate(self, hostname: str) -> None:
        if not self.enforcement:
            return
        if not self.allowed_domains:
            return
        hostname = hostname.lower().strip()
        for domain in self.allowed_domains:
            domain = domain.lower().strip()
            if hostname == domain or hostname.endswith(f".{domain}"):
                return
        raise ScopeViolationError(
            f"Target '{hostname}' is outside authorized scope: {self.allowed_domains}"
        )


def validate_url_scope(url: str, allowed_domains: list[str] | None = None) -> None:
    parsed = urlparse(url)
    hostname = parsed.hostname
    if hostname:
        validator = ScopeValidator(allowed_domains)
        validator.validate(hostname)
