from __future__ import annotations

import pytest

from bugfinder.core.types import (
    Confidence,
    FindingStatus,
    Severity,
    TargetType,
)


class TestTypes:
    def test_target_type_values(self) -> None:
        assert TargetType.WEBSITE.value == "website"
        assert TargetType.ANDROID.value == "android"

    def test_severity_order(self) -> None:
        severities = list(Severity)
        assert severities[0] == Severity.CRITICAL
        assert severities[-1] == Severity.INFO

    def test_confidence_values(self) -> None:
        assert Confidence.VERIFIED.value == "verified"
        assert Confidence.NEEDS_REVIEW.value == "needs_review"

    def test_finding_status(self) -> None:
        assert FindingStatus.OPEN.value == "open"
        assert FindingStatus.FALSE_POSITIVE.value == "false_positive"


class TestTargetTypeDetection:
    @pytest.mark.parametrize(
        "target,expected",
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
            ("unknown_target_xyz", TargetType.UNKNOWN),
        ],
    )
    def test_detect_target_type(self, target: str, expected: TargetType) -> None:
        from bugfinder.target.detector import detect_target_type

        assert detect_target_type(target) == expected


class TestSeverity:
    def test_risk_score(self) -> None:
        from bugfinder.core.types import RiskScore

        assert RiskScore.CRITICAL.value == 4
        assert RiskScore.NONE.value == 0
