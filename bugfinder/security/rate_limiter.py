from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from collections.abc import AsyncGenerator


class TokenBucket:
    def __init__(self, rate: float, capacity: int | None = None) -> None:
        self.rate = rate
        self.capacity = capacity or int(rate)
        self.tokens = float(self.capacity)
        self.last_refill = time.monotonic()

    def consume(self, tokens: float = 1.0) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_refill = now

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    async def wait(self, tokens: float = 1.0) -> None:
        while not self.consume(tokens):
            await asyncio.sleep(1.0 / self.rate)


class RateLimiter:
    def __init__(self, rate_per_second: int = 50) -> None:
        self.global_bucket = TokenBucket(rate_per_second)
        self.domain_buckets: dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(rate_per_second // 2)
        )

    async def acquire(self, domain: str | None = None) -> None:
        await self.global_bucket.wait()
        if domain:
            await self.domain_buckets[domain].wait()

    async def __aenter__(self) -> "RateLimiter":
        return self

    async def __aexit__(self, *args: object) -> None:
        pass
