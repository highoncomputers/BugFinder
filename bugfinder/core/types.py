from __future__ import annotations

import enum


class TargetType(str, enum.Enum):
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


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, enum.Enum):
    VERIFIED = "verified"
    LIKELY = "likely"
    NEEDS_REVIEW = "needs_review"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"
    ACKNOWLEDGED = "acknowledged"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentStatus(str, enum.Enum):
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
