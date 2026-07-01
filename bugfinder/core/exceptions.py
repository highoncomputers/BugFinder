from __future__ import annotations


class BugFinderError(Exception):
    """Base exception for all BugFinder errors."""


class ConfigError(BugFinderError):
    """Configuration related errors."""


class ScopeError(BugFinderError):
    """Assessment scope violation."""


class TargetDetectionError(BugFinderError):
    """Failed to detect target type."""


class AgentError(BugFinderError):
    """Agent execution error."""


class AIClientError(BugFinderError):
    """AI API client error."""


class PluginError(BugFinderError):
    """Plugin loading/execution error."""


class DatabaseError(BugFinderError):
    """Database operation error."""


class ReportError(BugFinderError):
    """Report generation error."""


class VerificationError(BugFinderError):
    """Finding verification error."""


class RateLimitError(BugFinderError):
    """Rate limit exceeded."""


class ScopeViolationError(ScopeError):
    """Target is outside authorized scope."""
