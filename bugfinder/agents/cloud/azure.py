from __future__ import annotations

import re

from bugfinder.agents.base import AgentContext, AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity
from bugfinder.utils.http import get


class AzureAgent(BaseAgent):
    category = "cloud"
    name = "azure"

    async def execute(self, context: AgentContext) -> AgentResult:
        findings = []
        target = context.target
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port:
            base_url += f":{target.port}"

        try:
            resp = await get(base_url, timeout=10)
            text = resp.text if hasattr(resp, "text") else ""

            blob_patterns = re.findall(r"[\w\-\.]+\.blob\.core\.windows\.net[\w\-\.\/]*", text)
            azure_patterns = re.findall(r"[\w\-\.]+\.azurewebsites\.net", text)
            azure_patterns2 = re.findall(r"[\w\-\.]+\.azurefd\.net", text)

            all_refs = list(set(blob_patterns + azure_patterns + azure_patterns2))

            for ref in all_refs:
                azure_url = f"https://{ref}"
                try:
                    azure_resp = await get(azure_url, timeout=10)
                    status = azure_resp.status_code if hasattr(azure_resp, "status_code") else 0
                    text_body = azure_resp.text if hasattr(azure_resp, "text") else ""

                    if status == 200 and "PublicAccess" not in text_body and "ResourceNotFound" not in text_body:
                        findings.append(
                            {
                                "title": "Azure Blob Storage Container Accessible",
                                "description": f"Azure blob container '{ref}' is publicly accessible.",
                                "severity": Severity.HIGH,
                                "confidence": Confidence.HIGH,
                                "category": "cloud",
                                "cwe_id": "200",
                                "owasp_category": "A01-Broken Access Control",
                                "cvss_score": 7.5,
                                "evidence": {"container": ref, "url": azure_url, "status": status},
                                "remediation": "Set Azure Storage firewall rules. Disable anonymous access on containers.",
                            }
                        )
                except Exception:
                    pass

        except Exception:
            pass

        return AgentResult(
            agent_name="azure",
            status="completed",
            findings=findings,
            summary=f"Found {len(findings)} Azure issues",
        )
