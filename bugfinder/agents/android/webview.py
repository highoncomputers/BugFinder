from __future__ import annotations

import re
from typing import Any
from xml.etree import ElementTree

from bugfinder.agents.base import BaseAgent, AgentContext, AgentResult
from bugfinder.core.types import Severity, Confidence


class AndroidWebViewAgent(BaseAgent):
    category = "android"
    name = "webview"

    async def execute(self, context: AgentContext) -> AgentResult:
        findings = []
        target = context.target
        apk_path = target.raw if hasattr(target, 'raw') else target.hostname

        try:
            import zipfile
            with zipfile.ZipFile(apk_path, 'r') as zf:
                # Read AndroidManifest.xml (binary XML - parse as text for basic checks)
                if 'AndroidManifest.xml' in zf.namelist():
                    manifest_data = zf.read('AndroidManifest.xml')

                    manifest_str = manifest_data.decode('utf-8', errors='replace')

                    webview_checks = [
                        ("setJavaScriptEnabled", "JavaScript enabled in WebView", Severity.HIGH),
                        ("allowFileAccess", "File access enabled in WebView", Severity.MEDIUM),
                        ("allowFileAccessFromFileURLs", "File URL access enabled in WebView", Severity.HIGH),
                        ("allowUniversalAccessFromFileURLs", "Universal file URL access in WebView", Severity.CRITICAL),
                        ("setAllowContentAccess", "Content access enabled in WebView", Severity.MEDIUM),
                    ]

                    for method, desc, sev in webview_checks:
                        if method in manifest_str:
                            findings.append({
                                "title": f"Insecure WebView Configuration: {desc}",
                                "description": f"Android app uses insecure WebView setting: {method}",
                                "severity": sev,
                                "confidence": Confidence.MEDIUM,
                                "category": "android",
                                "cwe_id": "79",
                                "owasp_category": "A03-Injection",
                                "cvss_score": 7.5 if sev == Severity.CRITICAL else 5.0,
                                "evidence": {"method": method, "description": desc},
                                "remediation": f"Disable {method} if not required. Use safe defaults for WebView configuration.",
                            })

                    if "onReceivedSslError" in manifest_str and "proceed" in manifest_str.lower():
                        findings.append({
                            "title": "WebView SSL Error Handler Ignores Certificate Errors",
                            "description": "WebView SSL error handler may be ignoring certificate validation errors.",
                            "severity": Severity.CRITICAL,
                            "confidence": Confidence.MEDIUM,
                            "category": "android",
                            "cwe_id": "295",
                            "owasp_category": "A02-Cryptographic Failures",
                            "cvss_score": 8.1,
                            "evidence": {"pattern": "onReceivedSslError with proceed"},
                            "remediation": "Properly validate SSL certificates in WebView. Do not call handler.proceed() unconditionally.",
                        })

        except Exception:
            pass

        return AgentResult(
            agent_name="webview",
            status="completed",
            findings=findings,
            summary=f"Found {len(findings)} Android WebView issues",
        )
