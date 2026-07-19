from __future__ import annotations

from ipaddress import ip_address, ip_network
from urllib.parse import urlparse

from bugfinder.core.exceptions import TargetDetectionError
from bugfinder.core.types import TargetType


class Target(str):
    def __new__(
        cls,
        raw: str,
        target_type: TargetType,
        normalized: str = "",
    ) -> Target:
        instance = str.__new__(cls, raw)
        instance._raw = raw
        instance.type = target_type
        instance.normalized = normalized or raw
        instance.metadata: dict = {}
        return instance

    @property
    def raw(self) -> str:
        return self._raw

    @property
    def hostname(self) -> str | None:
        parsed = urlparse(self.normalized)
        return parsed.hostname

    @property
    def scheme(self) -> str:
        parsed = urlparse(self.normalized)
        return parsed.scheme or "https"

    @property
    def port(self) -> int | None:
        parsed = urlparse(self.normalized)
        if parsed.port:
            return parsed.port
        if self.scheme == "https":
            return 443
        if self.scheme == "http":
            return 80
        return None


def parse_target(raw: str, target_type: TargetType | None = None) -> Target:
    raw = raw.strip()

    if target_type is None:
        from bugfinder.target.detector import detect_target_type

        target_type = detect_target_type(raw)

    if target_type in (TargetType.WEBSITE, TargetType.API, TargetType.GRAPHQL):
        parsed = urlparse(raw)
        if not parsed.scheme:
            raw = f"https://{raw}"
        return Target(raw, target_type, normalized=raw)

    if target_type == TargetType.IP_ADDRESS:
        try:
            ip_address(raw)
        except ValueError as e:
            raise TargetDetectionError(f"Invalid IP address: {raw}") from e
        return Target(raw, target_type)

    if target_type == TargetType.CIDR:
        try:
            ip_network(raw, strict=False)
        except ValueError as e:
            raise TargetDetectionError(f"Invalid CIDR: {raw}") from e
        return Target(raw, target_type)

    return Target(raw, target_type)
