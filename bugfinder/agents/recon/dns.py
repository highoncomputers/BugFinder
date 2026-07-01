from __future__ import annotations

import asyncio
import socket

from bugfinder.agents.base import AgentResult, BaseAgent


class DNSAgent(BaseAgent):
    name = "recon.dns"
    description = "DNS record discovery and subdomain enumeration"

    async def execute(self) -> AgentResult:
        hostname = self.context.target
        if self.context.target_type in ("website", "api", "domain"):
            from urllib.parse import urlparse

            parsed = urlparse(self.context.target)
            hostname = parsed.hostname or hostname

        assets = []
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

        for rtype in record_types:
            try:
                results = await asyncio.get_event_loop().run_in_executor(None, self._resolve, hostname, rtype)
                for r in results:
                    assets.append(
                        {
                            "id": f"dns-{rtype}-{r}",
                            "name": r,
                            "asset_type": "dns_record",
                            "properties": {"type": rtype, "source": hostname},
                        }
                    )
            except Exception:
                continue

        summary = f"Found {len(assets)} DNS records for {hostname}"
        return AgentResult(
            agent_name=self.name,
            status="completed",
            assets=assets,
            summary=summary,
        )

    def _resolve(self, hostname: str, rtype: str) -> list[str]:
        try:
            if rtype == "A":
                return [r[4][0] for r in socket.getaddrinfo(hostname, 0, socket.AF_INET)]
            if rtype == "AAAA":
                return [r[4][0] for r in socket.getaddrinfo(hostname, 0, socket.AF_INET6)]
            return []
        except socket.gaierror:
            return []
