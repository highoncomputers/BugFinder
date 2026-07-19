from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class RepeaterResult:
    def __init__(self, status_code: int, headers: dict[str, str], body: str, duration_ms: int, error: str | None = None):
        self.status_code = status_code
        self.headers = headers
        self.body = body
        self.duration_ms = duration_ms
        self.error = error


class Repeater:
    async def send(self, method: str, url: str, headers: str = "", body: str = "") -> RepeaterResult:
        import time

        start = time.monotonic()

        parsed_headers = {}
        for line in headers.split("\n"):
            line = line.strip()
            if ":" in line:
                k, v = line.split(":", 1)
                parsed_headers[k.strip()] = v.strip()

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(30)) as client:
                resp = await client.request(
                    method=method,
                    url=url,
                    headers=parsed_headers,
                    content=body if body else None,
                    follow_redirects=False,
                )
                elapsed = int((time.monotonic() - start) * 1000)
                return RepeaterResult(
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    body=resp.text,
                    duration_ms=elapsed,
                )
        except Exception as e:
            elapsed = int((time.monotonic() - start) * 1000)
            return RepeaterResult(
                status_code=0,
                headers={},
                body="",
                duration_ms=elapsed,
                error=str(e),
            )

    async def repeat_capture(self, capture: dict[str, Any], modified_request: str | None = None) -> RepeaterResult:
        if modified_request:
            lines = modified_request.strip().split("\n")
            first = lines[0].split(" ") if lines else []
            method = first[0] if len(first) > 1 else "GET"
            path = " ".join(first[1:-1]) if len(first) > 2 else (first[1] if len(first) > 1 else "/")
            host_line = next((line for line in lines[1:] if line.lower().startswith("host:")), "")
            host = host_line.split(":", 1)[1].strip() if ":" in host_line else capture.get("host", "localhost")
            port = capture.get("port", 80)
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{host}:{port}{path}"

            header_end = modified_request.find("\n\n")
            if header_end == -1:
                header_end = modified_request.find("\r\n\r\n")
            headers_text = ""
            body = ""
            if header_end > 0:
                headers_text = modified_request[:header_end]
                body = modified_request[header_end:].strip()
            else:
                headers_text = modified_request

        else:
            method = capture.get("method", "GET")
            host = capture.get("host", "localhost")
            port = capture.get("port", 80)
            path = capture.get("path", "/")
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{host}:{port}{path}"
            headers_text = capture.get("request_headers", "")
            body = capture.get("request_body", "")

        return await self.send(method, url, headers_text, body)
