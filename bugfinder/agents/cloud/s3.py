from __future__ import annotations

import re
from typing import Any

from bugfinder.agents.base import BaseAgent, AgentContext, AgentResult
from bugfinder.core.types import Severity, Confidence
from bugfinder.utils.http import get


class S3Agent(BaseAgent):
    category = "cloud"
    name = "s3"

    async def execute(self, context: AgentContext) -> AgentResult:
        findings = []
        target = context.target
        domain = target.hostname

        # Check page for S3 bucket references
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port:
            base_url += f":{target.port}"

        try:
            resp = await get(base_url, timeout=10)
            text = resp.text if hasattr(resp, 'text') else ""

            bucket_patterns = re.findall(r'[\w\-\.]+\.s3\.amazonaws\.com[\w\-\.\/]*', text)
            bucket_patterns2 = re.findall(r's3://[\w\-\.]+', text)
            bucket_patterns3 = re.findall(r'[\w\-\.]+\.s3[\-\w]*\.amazonaws\.com', text)

            all_buckets = list(set(bucket_patterns + bucket_patterns2 + bucket_patterns3))

            for bucket_ref in all_buckets:
                bucket_name = bucket_ref.replace("s3://", "").split(".")[0]
                # Try to access bucket
                try:
                    s3_url = f"https://{bucket_name}.s3.amazonaws.com"
                    s3_resp = await get(s3_url, timeout=10)
                    s3_text = s3_resp.text if hasattr(s3_resp, 'text') else ""
                    s3_status = s3_resp.status_code if hasattr(s3_resp, 'status_code') else 0

                    if s3_status == 200:
                        findings.append({
                            "title": "S3 Bucket Accessible",
                            "description": f"S3 bucket '{bucket_name}' is publicly accessible at {s3_url}.",
                            "severity": Severity.HIGH,
                            "confidence": Confidence.HIGH,
                            "category": "cloud",
                            "cwe_id": "200",
                            "owasp_category": "A01-Broken Access Control",
                            "cvss_score": 7.5,
                            "evidence": {"bucket": bucket_name, "url": s3_url, "status": s3_status},
                            "remediation": "Configure bucket policies to block public access. Use AWS Block Public Access settings.",
                        })

                        if "<ListBucketResult" in s3_text:
                            findings.append({
                                "title": "S3 Bucket Listing Enabled",
                                "description": f"S3 bucket '{bucket_name}' allows listing its contents anonymously.",
                                "severity": Severity.CRITICAL,
                                "confidence": Confidence.HIGH,
                                "category": "cloud",
                                "cwe_id": "200",
                                "owasp_category": "A01-Broken Access Control",
                                "cvss_score": 8.6,
                                "evidence": {"bucket": bucket_name, "listing_enabled": True},
                                "remediation": "Disable S3 bucket listing. Remove public access to bucket ACL.",
                            })

                    elif s3_status == 403:
                        pass  # Access denied is good
                except Exception:
                    pass

        except Exception:
            pass

        return AgentResult(
            agent_name="s3",
            status="completed",
            findings=findings,
            summary=f"Found {len(findings)} S3 issues",
        )
