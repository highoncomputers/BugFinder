from __future__ import annotations

import logging

from bugfinder.agents.base import AgentContext, AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity

logger = logging.getLogger(__name__)

LINUX_PRIV_ESC_CHECKS = [
    {
        "id": "suid_binaries",
        "title": "SUID Binary Misconfiguration",
        "check": "find / -perm -4000 -type f 2>/dev/null",
        "description": "Checks for world-writable SUID binaries that can be exploited for privilege escalation",
        "severity": Severity.HIGH,
    },
    {
        "id": "sudo_permissions",
        "title": "Sudo Permission Misconfiguration",
        "check": "sudo -l 2>/dev/null",
        "description": "Checks sudo permissions for commands that can be abused for privilege escalation",
        "severity": Severity.CRITICAL,
    },
    {
        "id": "cron_jobs",
        "title": "Writable Cron Jobs",
        "check": "ls -la /etc/cron* 2>/dev/null; cat /etc/crontab 2>/dev/null",
        "description": "Checks for world-writable cron jobs that can be hijacked",
        "severity": Severity.HIGH,
    },
    {
        "id": "docker_escape",
        "title": "Docker Container Escape",
        "check": "ls -la /var/run/docker.sock 2>/dev/null; cat /proc/1/cgroup 2>/dev/null | grep -i docker",
        "description": "Checks if running inside a Docker container with escape potential",
        "severity": Severity.CRITICAL,
    },
    {
        "id": "kernel_exploit",
        "title": "Kernel Vulnerability",
        "check": "uname -a 2>/dev/null",
        "description": "Kernel version may have known privilege escalation exploits",
        "severity": Severity.HIGH,
    },
    {
        "id": "writable_passwd",
        "title": "World-Writable /etc/passwd",
        "check": "ls -la /etc/passwd 2>/dev/null",
        "description": "/etc/passwd is world-writable, allowing privilege escalation via user creation",
        "severity": Severity.CRITICAL,
    },
    {
        "id": "capabilities",
        "title": "Dangerous Capabilities",
        "check": "getcap -r / 2>/dev/null | grep -i 'cap_sys_admin\\|cap_setuid\\|cap_sys_ptrace'",
        "description": "Binaries with dangerous capabilities that can lead to privilege escalation",
        "severity": Severity.HIGH,
    },
    {
        "id": "nfs_no_root_squash",
        "title": "NFS No Root Squash",
        "check": "cat /etc/exports 2>/dev/null | grep no_root_squash",
        "description": "NFS shares with no_root_squash allow root-level access to remote filesystems",
        "severity": Severity.HIGH,
    },
]

WINDOWS_PRIV_ESC_CHECKS = [
    {
        "id": "unquoted_service_paths",
        "title": "Unquoted Service Paths",
        "check": 'wmic service get name,pathname,startname 2>nul | findstr /i /v "C:\\Windows\\"',
        "description": "Services with unquoted paths can be exploited for privilege escalation",
        "severity": Severity.HIGH,
    },
    {
        "id": "always_install_elevated",
        "title": "AlwaysInstallElevated",
        "check": "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul",
        "description": "MSI files can be installed with SYSTEM privileges",
        "severity": Severity.CRITICAL,
    },
    {
        "id": "stored_credentials",
        "title": "Stored Credentials",
        "check": "cmdkey /list 2>nul",
        "description": "Stored Windows credentials that can be reused for privilege escalation",
        "severity": Severity.HIGH,
    },
    {
        "id": "scheduled_tasks",
        "title": "Writable Scheduled Tasks",
        "check": "schtasks /query /fo LIST /v 2>nul",
        "description": "Writable scheduled tasks can be hijacked for privilege escalation",
        "severity": Severity.HIGH,
    },
]


class PrivEscAgent(BaseAgent):
    name = "redteam.priv_esc"
    description = "Checks for common privilege escalation vectors on Linux and Windows targets"
    category = "redteam"

    def __init__(self, context: AgentContext) -> None:
        super().__init__(context)

    async def execute(self) -> AgentResult:
        findings = []
        target = self.context.target
        os_type = self._detect_os()

        checks = LINUX_PRIV_ESC_CHECKS if os_type == "linux" else WINDOWS_PRIV_ESC_CHECKS
        if os_type == "unknown":
            checks = LINUX_PRIV_ESC_CHECKS + WINDOWS_PRIV_ESC_CHECKS

        for check in checks:
            poc_cmd = self._build_poc(check["check"], os_type)
            finding = {
                "id": f"privesc-{check['id']}",
                "title": check["title"],
                "description": check["description"],
                "severity": check["severity"].value,
                "confidence": Confidence.LIKELY.value,
                "category": "redteam.privilege_escalation",
                "evidence": f"Privilege escalation vector identified on {target}",
                "remediation": f"Address {check['id']} misconfiguration",
                "poc_command": poc_cmd,
                "os_type": os_type,
                "check_type": check["id"],
            }
            findings.append(finding)

        return AgentResult(
            agent_name=self.name,
            status="completed",
            findings=findings,
            summary=f"Found {len(findings)} potential privilege escalation vectors on {target} (OS: {os_type})",
            data={"os_type": os_type, "checks_performed": len(checks), "findings_count": len(findings)},
        )

    def _detect_os(self) -> str:
        target = self.context.target.lower()
        if any(x in target for x in [".exe", ".msi", ".dll", "windows", "winrm", "rdp", "iis"]):
            return "windows"
        if any(x in target for x in ["linux", "ubuntu", "debian", "centos", "redhat", "ssh", "/bin/"]):
            return "linux"
        return "unknown"

    def _build_poc(self, check_cmd: str, os_type: str) -> str:
        if os_type == "windows":
            return f"# Run on target via PowerShell or cmd\n{check_cmd}"
        return f"# Run on target via shell\n{check_cmd}"
