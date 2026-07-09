from __future__ import annotations

import asyncio
import socket

from bugfinder.agents.base import AgentResult, BaseAgent

COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


class PortScanAgent(BaseAgent):
    name = "infra.port"
    description = "TCP port scanner"

    async def execute(self) -> AgentResult:
        target = self.context.target
        hostname = target

        from urllib.parse import urlparse

        if target.startswith("http"):
            parsed = urlparse(target)
            hostname = parsed.hostname or hostname
        if ":" in hostname and not hostname.startswith("["):
            hostname = hostname.split(":")[0]

        try:
            addr = socket.getaddrinfo(hostname, 80, socket.AF_INET)
            ip = addr[0][4][0]
        except socket.gaierror:
            return AgentResult(
                agent_name=self.name,
                status="completed",
                summary=f"Could not resolve {hostname}",
            )

        self.context.knowledge_graph.add_node(
            f"ip-{ip}",
            "ip_address",
            name=ip,
            source="port_scan",
        )
        self.context.knowledge_graph.add_edge(f"host-{hostname}", f"ip-{ip}", "resolves_to")

        open_ports = []
        sem = asyncio.Semaphore(50)

        async def scan_port(port: int) -> int | None:
            async with sem:
                try:
                    _, writer = await asyncio.wait_for(asyncio.open_connection(hostname, port), timeout=2)
                    writer.close()
                    await writer.wait_closed()
                    return port
                except (TimeoutError, OSError):
                    return None

        tasks = [scan_port(port) for port in COMMON_PORTS]
        results = await asyncio.gather(*tasks)

        findings = []
        assets = []
        for port in results:
            if port is not None:
                service = COMMON_PORTS.get(port, "unknown")
                open_ports.append(port)
                port_id = f"port-{ip}-{port}"
                assets.append(
                    {
                        "id": port_id,
                        "name": f"{hostname}:{port}",
                        "asset_type": "port",
                        "value": f"TCP/{port} ({service})",
                        "properties": {"port": port, "service": service, "protocol": "tcp", "ip": ip},
                    }
                )

                if service in ("SSH", "Telnet", "RDP", "VNC") and port in (22, 23, 3389, 5900):
                    findings.append(
                        {
                            "title": f"Remote Access Service Exposed: {service}",
                            "description": f"{service} is running on port {port} at {hostname}",
                            "severity": "medium",
                            "category": "exposed_service",
                            "evidence": {"host": hostname, "port": port, "service": service},
                        }
                    )

        summary = f"Scanned {len(COMMON_PORTS)} ports on {hostname} ({ip}), {len(open_ports)} open"
        for f in findings:
            f["id"] = f"port-finding-{findings.index(f)}"
        return AgentResult(
            agent_name=self.name,
            status="completed",
            assets=assets,
            findings=findings,
            summary=summary,
        )
