from __future__ import annotations

import enum


class TargetType(enum.StrEnum):
    WEBSITE = "website"
    API = "api"
    GRAPHQL = "graphql"
    SOAP = "soap"
    ANDROID = "android"
    SOURCE_CODE = "source_code"
    DOCKER = "docker"
    KUBERNETES = "kubernetes"
    CLOUD = "cloud"
    NETWORK = "network"
    IP_ADDRESS = "ip_address"
    CIDR = "cidr"
    DOMAIN = "domain"
    UNKNOWN = "unknown"


class Severity(enum.StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(enum.StrEnum):
    VERIFIED = "verified"
    LIKELY = "likely"
    NEEDS_REVIEW = "needs_review"
    HIGH = "likely"
    MEDIUM = "needs_review"
    LOW = "needs_review"


class FindingStatus(enum.StrEnum):
    OPEN = "open"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"
    ACKNOWLEDGED = "acknowledged"


class ScanStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentStatus(enum.StrEnum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class RiskScore(int, enum.Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


FRAMEWORK_MAP = {
    "cwe": "Common Weakness Enumeration",
    "owasp": "OWASP Top 10",
    "nist": "NIST SP 800-53",
    "pci": "PCI DSS",
    "iso27001": "ISO 27001",
}
