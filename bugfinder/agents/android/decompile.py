from __future__ import annotations

import os
import re
import zipfile

from bugfinder.agents.base import AgentResult, BaseAgent

ANDROID_PERMISSIONS_HIGH = [
    "CAMERA",
    "RECORD_AUDIO",
    "READ_CONTACTS",
    "READ_SMS",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE",
    "READ_CALL_LOG",
    "WRITE_CALL_LOG",
    "BIND_ACCESSIBILITY_SERVICE",
]

ANDROID_PERMISSIONS_CRITICAL = [
    "SYSTEM_ALERT_WINDOW",
    "INSTALL_PACKAGES",
    "DELETE_PACKAGES",
    "READ_LOGS",
    "BIND_NOTIFICATION_LISTENER_SERVICE",
    "REQUEST_INSTALL_PACKAGES",
    "MANAGE_EXTERNAL_STORAGE",
]


class DecompileAgent(BaseAgent):
    name = "android.decompile"
    description = "APK decompilation and manifest analysis"

    async def execute(self) -> AgentResult:
        target = self.context.target
        findings = []
        assets = []

        if not os.path.isfile(target) or not target.endswith(".apk"):
            return AgentResult(
                agent_name=self.name,
                status="completed",
                summary=f"Not an APK file: {target}",
            )

        try:
            with zipfile.ZipFile(target, "r") as apk:
                names = apk.namelist()
                assets.append(
                    {
                        "id": "apk-contents",
                        "name": target,
                        "asset_type": "android_apk",
                        "value": f"APK with {len(names)} entries",
                        "properties": {"file_count": len(names)},
                    }
                )

                if "AndroidManifest.xml" in names:
                    raw = apk.read("AndroidManifest.xml")
                    text = raw.decode("utf-8", errors="replace")

                    pkg_match = re.search(r'package="([^"]+)"', text)
                    if pkg_match:
                        assets.append(
                            {
                                "id": "apk-package",
                                "name": pkg_match.group(1),
                                "asset_type": "android_package",
                                "value": pkg_match.group(1),
                            }
                        )

                    exported = re.findall(r'android:exported=["\']true["\']', text)
                    if exported:
                        findings.append(
                            {
                                "title": f"Exported Components: {len(exported)}",
                                "description": f"{len(exported)} components have android:exported=true",
                                "severity": "medium",
                                "confidence": "verified",
                                "category": "android",
                                "evidence": {"exported_count": len(exported)},
                            }
                        )

                    debuggable = re.search(r'android:debuggable=["\']true["\']', text)
                    if debuggable:
                        findings.append(
                            {
                                "title": "APK is Debuggable",
                                "description": "The application is debuggable, allowing easier reverse engineering",
                                "severity": "high",
                                "confidence": "verified",
                                "category": "android",
                                "evidence": {"debuggable": True},
                            }
                        )

                    perms = re.findall(
                        r'android:name=["\']android\.permission\.([A-Z_]+)["\']',
                        text,
                    )
                    for perm in perms:
                        severity = (
                            "critical"
                            if perm in ANDROID_PERMISSIONS_CRITICAL
                            else ("high" if perm in ANDROID_PERMISSIONS_HIGH else "info")
                        )
                        if severity in ("critical", "high"):
                            findings.append(
                                {
                                    "title": f"Sensitive Permission: {perm}",
                                    "description": f"App requests {perm} permission ({severity} risk)",
                                    "severity": severity,
                                    "confidence": "verified",
                                    "category": "android",
                                    "evidence": {"permission": perm},
                                }
                            )

                    uses_cleartext = re.search(r'android:usesCleartextTraffic=["\']true["\']', text)
                    if uses_cleartext:
                        findings.append(
                            {
                                "title": "Cleartext Traffic Allowed",
                                "description": "App allows unencrypted HTTP traffic (usesCleartextTraffic=true)",
                                "severity": "high",
                                "confidence": "verified",
                                "category": "android",
                                "evidence": {"uses_cleartext": True},
                            }
                        )

                    allow_backup = re.search(r'android:allowBackup=["\']true["\']', text)
                    if allow_backup:
                        findings.append(
                            {
                                "title": "App Backup Enabled",
                                "description": "android:allowBackup=true allows data extraction via ADB backup",
                                "severity": "medium",
                                "confidence": "verified",
                                "category": "android",
                                "evidence": {"allow_backup": True},
                            }
                        )

                for name in names:
                    if name.endswith(".dex"):
                        dex_data = apk.read(name)
                        assets.append(
                            {
                                "id": f"dex-{name.replace('/', '_')}",
                                "name": name,
                                "asset_type": "android_dex",
                                "value": f"{len(dex_data):,} bytes",
                                "properties": {"size": len(dex_data)},
                            }
                        )

                        strings = self._extract_strings(dex_data)
                        import bugfinder.utils.crypto as crypto

                        secrets = crypto.detect_high_entropy_strings(strings)
                        for secret in secrets:
                            findings.append(
                                {
                                    "title": f"Potential Secret in DEX: {secret['pattern']}",
                                    "description": f"High-entropy string matching '{secret['pattern']}' in {name}",
                                    "severity": "critical",
                                    "confidence": "needs_review",
                                    "category": "secret_exposure",
                                    "evidence": {
                                        "dex": name,
                                        "pattern": secret["pattern"],
                                        "entropy": secret["entropy"],
                                    },
                                }
                            )

        except Exception as e:
            return AgentResult(
                agent_name=self.name,
                status="completed",
                summary=f"APK analysis error: {e}",
            )

        for f in findings:
            f["id"] = f"android-finding-{findings.index(f)}"
        summary = f"Analyzed APK: {len(findings)} findings, {len(assets)} assets"
        return AgentResult(
            agent_name=self.name,
            status="completed",
            assets=assets,
            findings=findings,
            summary=summary,
        )

    def _extract_strings(self, data: bytes) -> str:
        result = []
        current = []
        for byte in data:
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= 6:
                    result.append("".join(current))
                current = []
        if len(current) >= 6:
            result.append("".join(current))
        return "\n".join(result)
