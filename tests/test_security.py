from __future__ import annotations

import pytest

from bugfinder.core.exceptions import ScopeViolationError
from bugfinder.security.rate_limiter import RateLimiter
from bugfinder.security.scope import ScopeEnforcer


class TestScopeEnforcer:
    def test_no_enforcement_when_empty(self) -> None:
        enforcer = ScopeEnforcer(allowed_domains=[])
        enforcer.check_url("https://evil.com")  # Should not raise

    def test_allowed_domain_passes(self) -> None:
        enforcer = ScopeEnforcer(allowed_domains=["example.com"])
        enforcer.check_url("https://example.com/path?q=1")
        enforcer.check_url("https://sub.example.com/test")

    def test_blocked_domain_raises(self) -> None:
        enforcer = ScopeEnforcer(allowed_domains=["example.com"])
        with pytest.raises(ScopeViolationError):
            enforcer.check_url("https://evil.com")

    def test_wildcard_domain(self) -> None:
        enforcer = ScopeEnforcer(allowed_domains=["*.example.com"])
        enforcer.check_url("https://sub.example.com")
        enforcer.check_url("https://deep.sub.example.com")
        with pytest.raises(ScopeViolationError):
            enforcer.check_url("https://other.com")


class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_acquire(self) -> None:
        limiter = RateLimiter(rate_per_second=1000)
        await limiter.acquire("example.com")
        await limiter.acquire()  # Global only

    @pytest.mark.asyncio
    async def test_context_manager(self) -> None:
        async with RateLimiter(rate_per_second=1000) as limiter:
            await limiter.acquire("test.com")
