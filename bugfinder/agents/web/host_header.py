from __future__ import annotations

from bugfinder.agents.base import AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity
from bugfinder.utils.http import get


class HostHeaderAgent(BaseAgent):
    category = "web"
    name = "host_header"

    async def execute(self) -> AgentResult:
        findings = []
        target = self.context.target
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port:
            base_url += f":{target.port}"

        malicious_hosts = [
            "evil.com",
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "10.0.0.1",
            "192.168.1.1",
            target.hostname + ".evil.com",
        ]

        for bad_host in malicious_hosts:
            try:
                resp = await get(base_url, headers={"Host": bad_host}, timeout=10)
                text = resp.text if hasattr(resp, "text") else ""
                status = resp.status_code if hasattr(resp, "status_code") else 0

                if status == 200 and bad_host in text:
                    findings.append(
                        {
                            "title": "Host Header Injection",
                            "description": f"Server reflects malicious Host header '{bad_host}' in response.",
                            "severity": Severity.HIGH,
                            "confidence": Confidence.HIGH,
                            "category": "host-header",
                            "cwe_id": "444",
                            "owasp_category": "A01-Broken Access Control",
                            "cvss_score": 7.5,
                            "evidence": {"injected_host": bad_host, "reflected_in_body": True},
                            "remediation": "Validate the Host header against an allowlist. Do not reflect it without validation.",
                        }
                    )

                if status in (200, 302, 301) and bad_host in str(resp.headers if hasattr(resp, "headers") else ""):
                    findings.append(
                        {
                            "title": "Host Header Reflected in Response Headers",
                            "description": f"Host header '{bad_host}' reflected in response headers, enabling cache poisoning.",
                            "severity": Severity.HIGH,
                            "confidence": Confidence.HIGH,
                            "category": "host-header",
                            "cwe_id": "444",
                            "owasp_category": "A01-Broken Access Control",
                            "cvss_score": 7.5,
                            "evidence": {"injected_host": bad_host, "reflected_in_headers": True},
                            "remediation": "Do not reflect the Host header in Location or other response headers.",
                        }
                    )
            except Exception:
                pass

        # Password reset poisoning check
        pw_reset_paths = ["/reset", "/forgot-password", "/reset-password", "/auth/reset"]
        for path in pw_reset_paths:
            try:
                resp = await get(base_url + path, headers={"Host": "evil.com"}, timeout=10)
                if hasattr(resp, "headers"):
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location:
                        findings.append(
                            {
                                "title": "Password Reset Poisoning via Host Header",
                                "description": f"Password reset endpoint uses Host header for reset links: {path}",
                                "severity": Severity.CRITICAL,
                                "confidence": Confidence.MEDIUM,
                                "category": "host-header",
                                "cwe_id": "444",
                                "owasp_category": "A01-Broken Access Control",
                                "cvss_score": 9.1,
                                "evidence": {"path": path, "generated_link": location},
                                "remediation": "Use a configured server name instead of the Host header for generating reset links.",
                            }
                        )
            except Exception:
                pass

        return AgentResult(
            agent_name="host_header",
            status="completed",
            findings=findings,
            summary=f"Found {len(findings)} host header issues",
        )
