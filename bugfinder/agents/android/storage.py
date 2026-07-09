from __future__ import annotations

import re
from typing import Any

from bugfinder.agents.base import BaseAgent, AgentContext, AgentResult
from bugfinder.core.types import Severity, Confidence


class AndroidStorageAgent(BaseAgent):
    category = "android"
    name = "storage"

    async def execute(self, context: AgentContext) -> AgentResult:
        findings = []
        target = context.target
        apk_path = target.raw if hasattr(target, 'raw') else target.hostname

        try:
            import zipfile
            with zipfile.ZipFile(apk_path, 'r') as zf:
                namelist = zf.namelist()

                # Check for SQLite databases
                db_files = [n for n in namelist if n.endswith('.db') or n.endswith('.sqlite')]
                for db_file in db_files:
                    findings.append({
                        "title": "SQLite Database Found in APK",
                        "description": f"SQLite database file found at '{db_file}'. May contain sensitive data.",
                        "severity": Severity.MEDIUM,
                        "confidence": Confidence.HIGH,
                        "category": "android",
                        "cwe_id": "312",
                        "owasp_category": "A04-Insecure Design",
                        "cvss_score": 5.0,
                        "evidence": {"file": db_file},
                        "remediation": "Encrypt sensitive data at rest. Use Android EncryptedSharedPreferences or SQLCipher.",
                    })

                # Check SharedPreferences
                shared_prefs = [n for n in namelist if 'shared_prefs' in n.lower()]
                if shared_prefs:
                    findings.append({
                        "title": "SharedPreferences XML Files Found",
                        "description": f"Android SharedPreferences found ({len(shared_prefs)} files). May contain plaintext secrets.",
                        "severity": Severity.MEDIUM,
                        "confidence": Confidence.MEDIUM,
                        "category": "android",
                        "cwe_id": "312",
                        "owasp_category": "A04-Insecure Design",
                        "cvss_score": 4.3,
                        "evidence": {"files": shared_prefs[:5]},
                        "remediation": "Use EncryptedSharedPreferences for sensitive data. Never store API keys or tokens in plaintext.",
                    })

                # Check for world-readable flag in AndroidManifest
                if 'AndroidManifest.xml' in namelist:
                    manifest = zf.read('AndroidManifest.xml').decode('utf-8', errors='replace')
                    if 'android:sharedUserId' in manifest:
                        findings.append({
                            "title": "Shared User ID Used",
                            "description": "Android app uses sharedUserId, which may allow data access by other apps with same ID.",
                            "severity": Severity.LOW,
                            "confidence": Confidence.MEDIUM,
                            "category": "android",
                            "cwe_id": "200",
                            "owasp_category": "A01-Broken Access Control",
                            "cvss_score": 3.5,
                            "evidence": {"shared_user_id": True},
                            "remediation": "Avoid using sharedUserId. Isolate app data per application.",
                        })

                    if 'MODE_WORLD_READABLE' in manifest or 'MODE_WORLD_WRITEABLE' in manifest:
                        findings.append({
                            "title": "World-Readable or World-Writeable Mode",
                            "description": "App uses MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE for files.",
                            "severity": Severity.HIGH,
                            "confidence": Confidence.HIGH,
                            "category": "android",
                            "cwe_id": "200",
                            "owasp_category": "A01-Broken Access Control",
                            "cvss_score": 6.5,
                            "evidence": {"insecure_mode": True},
                            "remediation": "Use MODE_PRIVATE for all files. Use FileProvider for sharing files with other apps.",
                        })

                # Check for realm files
                realm_files = [n for n in namelist if '.realm' in n.lower()]
                if realm_files:
                    findings.append({
                        "title": "Realm Database Found",
                        "description": f"Realm database file found: {realm_files}. Realm files are not encrypted by default.",
                        "severity": Severity.MEDIUM,
                        "confidence": Confidence.MEDIUM,
                        "category": "android",
                        "cwe_id": "312",
                        "owasp_category": "A04-Insecure Design",
                        "cvss_score": 5.0,
                        "evidence": {"files": realm_files},
                        "remediation": "Enable Realm encryption with a 64-bit key stored in Android Keystore.",
                    })

        except Exception:
            pass

        return AgentResult(
            agent_name="storage",
            status="completed",
            findings=findings,
            summary=f"Found {len(findings)} Android storage issues",
        )
