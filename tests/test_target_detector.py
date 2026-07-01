from __future__ import annotations

import pytest

from bugfinder.core.types import TargetType
from bugfinder.target.detector import detect_target_type, normalize_target
from bugfinder.target.parsers import parse_target


class TestDetectTargetType:
    @pytest.mark.parametrize(
        "target,expected_type",
        [
            ("https://example.com", TargetType.WEBSITE),
            ("http://example.com", TargetType.WEBSITE),
            ("https://api.example.com/v1", TargetType.API),
            ("https://example.com/graphql", TargetType.GRAPHQL),
            ("app.apk", TargetType.ANDROID),
            ("192.168.1.1", TargetType.IP_ADDRESS),
            ("10.0.0.0/24", TargetType.CIDR),
            ("example.com", TargetType.DOMAIN),
            ("Dockerfile", TargetType.DOCKER),
            ("swagger.json", TargetType.API),
        ],
    )
    def test_detect(self, target: str, expected_type: TargetType) -> None:
        assert detect_target_type(target) == expected_type


class TestNormalizeTarget:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("example.com", "https://example.com"),
            ("https://example.com", "https://example.com"),
            ("192.168.1.1", "192.168.1.1"),
            ("api.example.com/v1", "https://api.example.com/v1"),
        ],
    )
    def test_normalize(self, raw: str, expected: str) -> None:
        assert normalize_target(raw) == expected


class TestTargetParser:
    def test_parse_website(self) -> None:
        t = parse_target("https://example.com")
        assert t.type == TargetType.WEBSITE
        assert t.hostname == "example.com"
        assert t.scheme == "https"

    def test_parse_ip(self) -> None:
        t = parse_target("192.168.1.1", TargetType.IP_ADDRESS)
        assert t.type == TargetType.IP_ADDRESS

    def test_parse_cidr(self) -> None:
        t = parse_target("10.0.0.0/24", TargetType.CIDR)
        assert t.type == TargetType.CIDR
