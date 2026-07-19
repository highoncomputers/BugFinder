from __future__ import annotations

import re

from bugfinder.agents.base import AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity
from bugfinder.utils.http import get


class GCPAgent(BaseAgent):
    category = "cloud"
    name = "gcp"

    async def execute(self) -> AgentResult:
        findings = []
        target = self.context.target
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port:
            base_url += f":{target.port}"

        try:
            resp = await get(base_url, timeout=10)
            text = resp.text if hasattr(resp, "text") else ""

            storage_patterns = re.findall(r"[\w\-\.]+\.storage\.googleapis\.com[\w\-\.\/]*", text)
            bucket_patterns = re.findall(r"[\w\-\.]+\.appspot\.com", text)
            firebase_patterns = re.findall(r"[\w\-\.]+\.firebaseio\.com", text)

            gcp_refs = list(set(storage_patterns + bucket_patterns + firebase_patterns))

            for ref in gcp_refs:
                gcp_url = f"https://{ref}"
                try:
                    gcp_resp = await get(gcp_url, timeout=10)
                    status = gcp_resp.status_code if hasattr(gcp_resp, "status_code") else 0
                    if status == 200:
                        findings.append(
                            {
                                "title": "Google Cloud Storage Bucket Accessible",
                                "description": f"GCP bucket '{ref}' is publicly accessible.",
                                "severity": Severity.HIGH,
                                "confidence": Confidence.HIGH,
                                "category": "cloud",
                                "cwe_id": "200",
                                "owasp_category": "A01-Broken Access Control",
                                "cvss_score": 7.5,
                                "evidence": {"bucket": ref, "url": gcp_url, "status": status},
                                "remediation": "Configure uniform bucket-level access. Block public access at the project level.",
                            }
                        )
                except Exception:
                    pass

        except Exception:
            pass

        # Check metadata endpoints (SSRF target validation)
        if target.hostname in ("localhost", "127.0.0.1", "0.0.0.0"):
            try:
                meta_resp = await get(
                    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                    headers={"Metadata-Flavor": "Google"},
                    timeout=5,
                )
                if hasattr(meta_resp, "status_code") and meta_resp.status_code == 200:
                    findings.append(
                        {
                            "title": "GCP Metadata Endpoint Accessible",
                            "description": "GCP metadata endpoint is accessible, which may expose service account tokens.",
                            "severity": Severity.CRITICAL,
                            "confidence": Confidence.HIGH,
                            "category": "cloud",
                            "cwe_id": "200",
                            "owasp_category": "A01-Broken Access Control",
                            "cvss_score": 9.8,
                            "evidence": {"metadata_accessible": True},
                            "remediation": "Block access to 169.254.169.254 and metadata.google.internal at the network level.",
                        }
                    )
            except Exception:
                pass

        return AgentResult(
            agent_name="gcp",
            status="completed",
            findings=findings,
            summary=f"Found {len(findings)} GCP issues",
        )
