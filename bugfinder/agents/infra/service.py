from __future__ import annotations

from urllib.parse import urlparse

from bugfinder.agents.base import AgentResult, BaseAgent

SERVICE_BANNERS: dict[int, str] = {
    21: b"220",
    22: b"SSH",
    25: b"220",
    80: b"HTTP",
    110: b"+OK",
    143: b"* OK",
    443: b"HTTP",
    3306: b"mysql",
    5432: b"PostgreSQL",
    6379: b"+OK",
    27017: b"MongoDB",
}


class ServiceDetectAgent(BaseAgent):
    name = "infra.service"
    description = "Service version detection via banners"

    async def execute(self) -> AgentResult:
        target = self.context.target
        hostname = target
        if target.startswith("http"):
            parsed = urlparse(target)
            hostname = parsed.hostname or hostname
        if ":" in hostname and not hostname.startswith("["):
            hostname = hostname.split(":")[0]

        findings = []
        assets = []

        for port, banner_start in SERVICE_BANNERS.items():
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(hostname, port), timeout=3)
                banner = await asyncio.wait_for(reader.read(1024), timeout=3)
                writer.close()
                await writer.wait_closed()

                if banner.strip():
                    banner_text = banner.decode("utf-8", errors="replace").strip()
                    assets.append(
                        {
                            "id": f"svc-{hostname}-{port}",
                            "name": f"{hostname}:{port}",
                            "asset_type": "service",
                            "value": banner_text[:100],
                            "properties": {"port": port, "banner": banner_text[:200]},
                        }
                    )

                    if "220" in banner_text[:10] and port == 21:
                        findings.append(
                            {
                                "title": f"FTP Service Detected on Port {port}",
                                "description": f"FTP banner: {banner_text[:80]}",
                                "severity": "info",
                                "category": "service_detection",
                                "evidence": {"host": hostname, "port": port, "banner": banner_text[:200]},
                            }
                        )
            except (OSError, asyncio.TimeoutError, UnicodeDecodeError):
                continue


        for f in findings:
            f["id"] = f"svc-finding-{findings.index(f)}"
        summary = f"Detected {len(assets)} services on {hostname}"
        return AgentResult(
            agent_name=self.name,
            status="completed",
            assets=assets,
            findings=findings,
            summary=summary,
        )
