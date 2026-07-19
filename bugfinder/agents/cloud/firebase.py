from __future__ import annotations

import re

from bugfinder.agents.base import AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity
from bugfinder.utils.http import get


class FirebaseAgent(BaseAgent):
    category = "cloud"
    name = "firebase"

    async def execute(self) -> AgentResult:
        findings = []
        target = self.context.target
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port:
            base_url += f":{target.port}"

        try:
            resp = await get(base_url, timeout=10)
            text = resp.text if hasattr(resp, "text") else ""

            firebase_refs = re.findall(r"[\w\-\.]+\.firebaseio\.com", text)
            firebase_apps = re.findall(r"[\w\-]+\.firebaseapp\.com", text)
            firebase_configs = re.findall(r'apiKey:\s*["\'][^"\']+["\']', text)
            firebase_ids = re.findall(r'projectId:\s*["\'][^"\']+["\']', text)
            firebase_db = re.findall(r'databaseURL:\s*["\'][^"\']+["\']', text)

            all_urls = list(set(firebase_refs + firebase_apps))

            for fb_url_ref in all_urls:
                fb_url = f"https://{fb_url_ref}/.json"
                try:
                    fb_resp = await get(fb_url, timeout=10)
                    status = fb_resp.status_code if hasattr(fb_resp, "status_code") else 0
                    body = fb_resp.text if hasattr(fb_resp, "text") else ""

                    if status == 200 and body.strip() not in ("null", "{}", ""):
                        findings.append(
                            {
                                "title": "Firebase Database Openly Accessible",
                                "description": f"Firebase Realtime Database at {fb_url_ref} is accessible without authentication.",
                                "severity": Severity.CRITICAL,
                                "confidence": Confidence.HIGH,
                                "category": "cloud",
                                "cwe_id": "200",
                                "owasp_category": "A01-Broken Access Control",
                                "cvss_score": 9.8,
                                "evidence": {"firebase_url": fb_url_ref, "data_preview": body[:500]},
                                "remediation": "Configure Firebase Realtime Database Rules to require authentication. Use Firebase Security Rules.",
                            }
                        )
                except Exception:
                    pass

            if firebase_configs or firebase_ids:
                findings.append(
                    {
                        "title": "Firebase Configuration Exposed",
                        "description": "Firebase configuration details found in client-side code.",
                        "severity": Severity.LOW,
                        "confidence": Confidence.HIGH,
                        "category": "cloud",
                        "cwe_id": "200",
                        "owasp_category": "A05-Security Misconfiguration",
                        "cvss_score": 3.7,
                        "evidence": {
                            "api_keys_found": len(firebase_configs),
                            "project_ids_found": len(firebase_ids),
                            "database_urls_found": len(firebase_db),
                        },
                        "remediation": "Firebase config is intended to be public, but ensure Security Rules are properly configured.",
                    }
                )

        except Exception:
            pass

        return AgentResult(
            agent_name="firebase",
            status="completed",
            findings=findings,
            summary=f"Found {len(findings)} Firebase issues",
        )
