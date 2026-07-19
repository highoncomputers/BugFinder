from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime

import httpx

from bugfinder.proxy.capture import ProxyCaptureStore

logger = logging.getLogger(__name__)


class ProxyServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 8081, capture_store: ProxyCaptureStore | None = None):
        self.host = host
        self.port = port
        self.capture = capture_store or ProxyCaptureStore()
        self._server: asyncio.AbstractServer | None = None
        self._running = False

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        self._running = True
        logger.info(f"Proxy server listening on {self.host}:{self.port}")

    async def stop(self) -> None:
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        await self.capture.flush()
        logger.info("Proxy server stopped")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        remote = writer.get_extra_info("peername")
        remote_addr = f"{remote[0]}:{remote[1]}" if remote else "unknown"

        try:
            raw_request = await asyncio.wait_for(reader.read(65536), timeout=10)
            if not raw_request:
                return

            request_text = raw_request.decode("utf-8", errors="replace")
            method, host, port, path, req_headers, req_body = self._parse_request(request_text)

            if not host:
                writer.close()
                return

            capture_id = uuid.uuid4().hex
            start = datetime.now(UTC)

            status_code, resp_headers_text, resp_body = await self._forward_request(
                method, host, port, path, req_headers, req_body
            )

            elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)

            await self.capture.save(
                {
                    "id": capture_id,
                    "method": method,
                    "host": host,
                    "port": port,
                    "path": path,
                    "request_headers": self._format_headers_for_storage(req_headers),
                    "request_body": req_body,
                    "status_code": status_code,
                    "response_headers": resp_headers_text,
                    "response_body": resp_body,
                    "content_type": self._extract_content_type(resp_headers_text),
                    "duration_ms": elapsed,
                    "size_bytes": len(resp_body) if resp_body else 0,
                    "remote_addr": remote_addr,
                    "tags": "",
                }
            )

            response_raw = self._build_response(status_code, resp_headers_text, resp_body)
            writer.write(response_raw.encode("utf-8", errors="replace"))
            await writer.drain()

        except TimeoutError:
            logger.debug(f"Timeout from {remote_addr}")
        except Exception as e:
            logger.debug(f"Proxy error from {remote_addr}: {e}")
        finally:
            try:
                writer.close()
            except Exception:
                pass

    def _parse_request(self, raw: str) -> tuple[str, str, int, str, dict[str, str], str]:
        lines = raw.split("\r\n")
        first = lines[0].split(" ") if lines else []
        method = first[0] if len(first) > 0 else "GET"
        url_path = first[1] if len(first) > 1 else "/"

        host = "localhost"
        port = 80

        headers: dict[str, str] = {}
        body_start = raw.find("\r\n\r\n")
        header_lines = lines[1:]
        if body_start > 0:
            header_text = raw[:body_start]
            header_lines = header_text.split("\r\n")[1:]

        for line in header_lines:
            if ":" in line and not line.startswith(" "):
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
                if k.strip().lower() == "host":
                    host_part = v.strip()
                    if ":" in host_part:
                        host, port_str = host_part.split(":", 1)
                        port = int(port_str)
                    else:
                        host = host_part

        body = ""
        if body_start > 0:
            body = raw[body_start + 4 :]

        path = url_path
        if url_path.startswith("http"):
            from urllib.parse import urlparse

            parsed = urlparse(url_path)
            host = parsed.hostname or host
            port = parsed.port or port
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query

        return method, host, port, path, headers, body

    async def _forward_request(
        self, method: str, host: str, port: int, path: str, headers: dict[str, str], body: str
    ) -> tuple[int, str, str]:
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{host}:{port}{path}"

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(10)) as client:
                resp = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=body if body else None,
                    follow_redirects=False,
                )
                resp_headers = "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                resp_body = resp.text
                return resp.status_code, resp_headers, resp_body
        except Exception as e:
            return 502, "Content-Type: text/plain", f"Proxy Error: {e}"

    def _build_response(self, status_code: int, headers: str, body: str) -> str:
        status_text = {
            200: "OK",
            301: "Moved",
            302: "Found",
            304: "Not Modified",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error",
            502: "Bad Gateway",
            503: "Service Unavailable",
        }.get(status_code, "Unknown")
        return f"HTTP/1.1 {status_code} {status_text}\r\n{headers}\r\n\r\n{body}"

    def _extract_content_type(self, headers_text: str) -> str:
        for line in headers_text.split("\r\n"):
            if line.lower().startswith("content-type:"):
                return line.split(":", 1)[1].strip()
        return ""

    def _format_headers_for_storage(self, headers: dict[str, str]) -> str:
        return "\r\n".join(f"{k}: {v}" for k, v in headers.items())
