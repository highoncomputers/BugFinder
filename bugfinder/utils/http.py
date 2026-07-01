from __future__ import annotations

from typing import Any

import httpx

from bugfinder.core.config import settings
from bugfinder.security.rate_limiter import RateLimiter


_default_headers = {
    "User-Agent": settings.user_agent,
    "Accept": "*/*",
}

_rate_limiter = RateLimiter(settings.rate_limit_per_second)


async def request(
    method: str,
    url: str,
    **kwargs: Any,
) -> httpx.Response:
    from urllib.parse import urlparse

    domain = urlparse(url).hostname
    await _rate_limiter.acquire(domain)

    headers = {**_default_headers, **kwargs.pop("headers", {})}
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(settings.request_timeout),
        follow_redirects=True,
        verify=False,
    ) as client:
        response = await client.request(method, url, headers=headers, **kwargs)
        return response


async def get(url: str, **kwargs: Any) -> httpx.Response:
    return await request("GET", url, **kwargs)


async def post(url: str, **kwargs: Any) -> httpx.Response:
    return await request("POST", url, **kwargs)
