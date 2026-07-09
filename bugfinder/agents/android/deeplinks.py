from __future__ import annotations

import re
from typing import Any

from bugfinder.agents.base import BaseAgent, AgentContext, AgentResult
from bugfinder.core.types import Severity, Confidence


class DeepLinkAgent(BaseAgent):
    category = "android"
    name = "deeplinks"

    async def execute(self, context: AgentContext) -> AgentResult:
        findings = []
        target = context.target
        apk_path = target.raw if hasattr(target, 'raw') else target.hostname

        try:
            import zipfile
            with zipfile.ZipFile(apk_path, 'r') as zf:
                namelist = zf.namelist()

                if 'AndroidManifest.xml' not in namelist:
                    return AgentResult(
                        agent_name="deeplinks",
                        status="completed",
                        findings=[],
                        summary="No AndroidManifest.xml found",
                    )

                manifest = zf.read('AndroidManifest.xml').decode('utf-8', errors='replace')

                intent_filters = re.findall(
                    r'<intent-filter>.*?</intent-filter>',
                    manifest,
                    re.DOTALL | re.IGNORECASE,
                )

                deep_links = []
                for i, intent_filter in enumerate(intent_filters):
                    data_uris = re.findall(
                        r'android:scheme\s*=\s*["\']([^"\']+)["\'].*?android:host\s*=\s*["\']([^"\']+)["\']',
                        intent_filter,
                        re.DOTALL,
                    )
                    if data_uris:
                        for scheme, host in data_uris:
                            deep_links.append({
                                "scheme": scheme,
                                "host": host,
                                "uri": f"{scheme}://{host}",
                            })

                    data_uris_short = re.findall(
                        r'android:host\s*=\s*["\']([^"\']+)["\'].*?android:scheme\s*=\s*["\']([^"\']+)["\']',
                        intent_filter,
                        re.DOTALL,
                    )
                    for host, scheme in data_uris_short:
                        if not any(d["uri"] == f"{scheme}://{host}" for d in deep_links):
                            deep_links.append({
                                "scheme": scheme,
                                "host": host,
                                "uri": f"{scheme}://{host}",
                            })

                # Check for exported activities with intent filters (accessible from other apps)
                activities = re.findall(
                    r'<activity[^>]*>.*?</activity>',
                    manifest,
                    re.DOTALL | re.IGNORECASE,
                )

                for activity in activities:
                    exported = re.search(r'android:exported\s*=\s*["\']([^"\']+)["\']', activity, re.IGNORECASE)
                    has_intent_filter = '<intent-filter>' in activity
                    activity_name = re.search(r'android:name\s*=\s*["\']([^"\']+)["\']', activity, re.IGNORECASE)
                    act_name = activity_name.group(1) if activity_name else "unknown"

                    if has_intent_filter and (exported is None or exported.group(1).lower() == "true"):
                        findings.append({
                            "title": "Exported Activity with Intent Filter",
                            "description": f"Activity '{act_name}' is exported and has intent filters, making it accessible from other apps.",
                            "severity": Severity.MEDIUM,
                            "confidence": Confidence.MEDIUM,
                            "category": "android",
                            "cwe_id": "926",
                            "owasp_category": "A01-Broken Access Control",
                            "cvss_score": 5.5,
                            "evidence": {"activity": act_name, "intent_filters": len(deep_links)},
                            "remediation": "Set android:exported=false if inter-app invocation is not required. Validate incoming intents.",
                        })

                if deep_links:
                    findings.append({
                        "title": "Deep Links Detected",
                        "description": f"Found {len(deep_links)} deep link URIs in the application.",
                        "severity": Severity.INFO,
                        "confidence": Confidence.HIGH,
                        "category": "android",
                        "cwe_id": "926",
                        "owasp_category": "A01-Broken Access Control",
                        "cvss_score": 0.0,
                        "evidence": {"deep_links": deep_links},
                        "remediation": "Verify deep link verification with Digital Asset Links. Validate all deep link parameters.",
                    })

        except Exception:
            pass

        return AgentResult(
            agent_name="deeplinks",
            status="completed",
            findings=findings,
            summary=f"Found {len(findings)} deep link issues",
        )
