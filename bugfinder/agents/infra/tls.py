from __future__ import annotations

import asyncio
import ssl
from datetime import UTC, datetime
from urllib.parse import urlparse

from bugfinder.agents.base import AgentResult, BaseAgent

WEAK_CIPHERS = [
    "RC4",
    "DES",
    "3DES",
    "MD5",
    "SHA1",
    "EXPORT",
    "NULL",
    "ANON",
    "aNULL",
    "eNULL",
]


class TLSScanAgent(BaseAgent):
    name = "infra.tls"
    description = "TLS/SSL configuration scanner"

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

        for port in [443, 8443]:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port, ssl=ctx, server_hostname=hostname),
                    timeout=10,
                )
                sock = writer.transport.get_extra_info("ssl_object")
                if sock:
                    cert = sock.getpeercert()
                    version = sock.version()
                    cipher = sock.cipher()

                    assets.append(
                        {
                            "id": f"tls-{hostname}-{port}",
                            "name": f"{hostname}:{port}",
                            "asset_type": "certificate",
                            "value": f"TLS {version}",
                            "properties": {
                                "port": port,
                                "version": version,
                                "cipher": cipher[0] if cipher else "unknown",
                                "cipher_bits": cipher[1] if cipher else 0,
                            },
                        }
                    )

                    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
                        findings.append(
                            {
                                "title": f"Outdated TLS Version: {version}",
                                "description": f"{hostname}:{port} uses {version}, which is deprecated",
                                "severity": "high",
                                "category": "tls",
                                "evidence": {"host": hostname, "port": port, "version": version},
                            }
                        )

                    if cipher:
                        cipher_name = cipher[0]
                        for weak in WEAK_CIPHERS:
                            if weak in cipher_name.upper():
                                findings.append(
                                    {
                                        "title": f"Weak Cipher: {cipher_name}",
                                        "description": f"{hostname}:{port} uses weak cipher {cipher_name}",
                                        "severity": "high",
                                        "category": "tls",
                                        "evidence": {"host": hostname, "port": port, "cipher": cipher_name},
                                    }
                                )
                                break

                    if cert:
                        exp = cert.get("notAfter", "")
                        if exp:
                            try:
                                exp_date = datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
                                days_left = (exp_date - datetime.now(UTC)).days
                                if days_left < 30:
                                    severity = "high" if days_left < 7 else "medium"
                                    findings.append(
                                        {
                                            "title": "SSL Certificate Expiring Soon",
                                            "description": f"Certificate expires in {days_left} days ({exp})",
                                            "severity": severity,
                                            "category": "tls",
                                            "evidence": {
                                                "host": hostname,
                                                "port": port,
                                                "expires": exp,
                                                "days_left": days_left,
                                            },
                                        }
                                    )
                            except (ValueError, KeyError):
                                pass

                writer.close()
                await writer.wait_closed()

            except (TimeoutError, OSError, ssl.SSLError):
                continue

        for f in findings:
            f["id"] = f"tls-finding-{findings.index(f)}"
        summary = f"Scanned TLS on {hostname}, {len(findings)} issues found"
        return AgentResult(
            agent_name=self.name,
            status="completed",
            assets=assets,
            findings=findings,
            summary=summary,
        )
