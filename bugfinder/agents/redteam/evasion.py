from __future__ import annotations

import logging
import random
import re

from bugfinder.agents.base import AgentContext, AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity

logger = logging.getLogger(__name__)

WAF_SIGNATURES = {
    "cloudflare": ["__cfduid", "cf-ray", "_cf_", "cloudflare-nginx"],
    "cloudfront": ["x-amz-cf-id", "x-amz-cf-pop", "cloudfront"],
    "akamai": ["akamai", "akavpma_", "X-Akamai-"],
    "fastly": ["x-fastly-", "fastly-backend-", "X-Served-By"],
    "modsecurity": ["ModSecurity", "NOYB", "webknight"],
    "aws_waf": ["x-amzn-requestid", "x-amzn-trace-id", "awswaf"],
    "f5_bigip": ["BigIP", "TS", "F5", "X-Cnection"],
    "sucuri": ["sucuri", "X-Sucuri-", "Sucuri/Cloudproxy"],
    "imperva": ["incapsula", "X-Iinfo", "imperva"],
    "barracuda": ["barracuda", "Barracuda"],
}

EVASION_TECHNIQUES = [
    {
        "id": "case_permutation",
        "name": "Case Permutation",
        "description": "Randomizes character case in SQL keywords to bypass simple WAF rules",
        "apply": lambda payload: "".join(random.choice([c.upper(), c.lower()]) for c in payload),
    },
    {
        "id": "url_encoding",
        "name": "Double URL Encoding",
        "description": "Double-encodes special characters to bypass WAF decoding",
        "apply": lambda payload: "".join(f"%{hex(ord(c))[2:].upper()}" if c in "<>'\"&()/" else c for c in payload),
    },
    {
        "id": "comment_injection",
        "name": "SQL Comment Injection",
        "description": "Injects SQL comments between keywords to break signature patterns",
        "apply": lambda payload: re.sub(
            r"\b(SELECT|UNION|INSERT|DROP|DELETE|UPDATE|OR|AND)\b",
            lambda m: m.group(1)[0] + "/**/" + m.group(1)[1:],
            payload,
            flags=re.IGNORECASE,
        ),
    },
    {
        "id": "hex_encoding",
        "name": "Hex Encoding",
        "description": "Encodes payload strings as hex to bypass string-based signatures",
        "apply": lambda payload: "0x" + payload.encode().hex(),
    },
    {
        "id": "null_byte",
        "name": "Null Byte Injection",
        "description": "Injects null bytes to truncate payloads at WAF level while preserving server-side execution",
        "apply": lambda payload: "%00".join(payload[i : i + 50] for i in range(0, len(payload), 50)),
    },
    {
        "id": "unicode_normalization",
        "name": "Unicode Normalization Bypass",
        "description": "Uses Unicode characters that normalize to ASCII equivalents",
        "apply": lambda payload: payload.replace("<", "＜").replace(">", "＞").replace("'", "＇"),
    },
    {
        "id": "parameter_pollution",
        "name": "HTTP Parameter Pollution",
        "description": "Duplicates parameters to confuse WAF while preserving application logic",
        "apply": lambda payload: f"id=1&id={payload}&id=3",
    },
]


class EvasionAgent(BaseAgent):
    name = "redteam.evasion"
    description = "WAF detection, fingerprinting, and payload obfuscation for evasion"
    category = "redteam"

    def __init__(self, context: AgentContext) -> None:
        super().__init__(context)

    async def execute(self) -> AgentResult:
        findings = []

        target = self.context.target
        waf_detected = None
        waf_headers = {}

        try:
            from bugfinder.utils.http import get

            resp = await get(target, timeout=15)
            response_headers = dict(resp.headers) if hasattr(resp, "headers") else {}

            for waf_name, signatures in WAF_SIGNATURES.items():
                for sig in signatures:
                    for key, val in response_headers.items():
                        if sig.lower() in key.lower() or sig.lower() in str(val).lower():
                            waf_detected = waf_name
                            waf_headers[key] = val
                            break
                    if waf_detected:
                        break
                if waf_detected:
                    break

            if waf_detected:
                finding = {
                    "id": f"waf-detected-{waf_detected}",
                    "title": f"WAF Detected: {waf_detected}",
                    "description": f"Web Application Firewall ({waf_detected}) detected on {target}",
                    "severity": Severity.INFO.value,
                    "confidence": Confidence.VERIFIED.value,
                    "category": "redteam.evasion",
                    "evidence": f"WAF identified via response headers: {waf_headers}",
                    "remediation": "Use evasion techniques below to bypass WAF rules",
                    "waf_name": waf_detected,
                    "waf_headers": waf_headers,
                }
                findings.append(finding)

        except Exception as e:
            logger.warning("Failed to detect WAF on %s: %s", target, e)

        for tech in EVASION_TECHNIQUES:
            sample_payload = "' OR 1=1 --"
            try:
                obfuscated = tech["apply"](sample_payload)
            except Exception:
                obfuscated = sample_payload

            finding = {
                "id": f"evasion-{tech['id']}",
                "title": f"Evasion: {tech['name']}",
                "description": tech["description"],
                "severity": Severity.INFO.value,
                "confidence": Confidence.VERIFIED.value,
                "category": "redteam.evasion",
                "evidence": f"Original: {sample_payload}\nObfuscated: {obfuscated}",
                "remediation": "Update WAF rules to detect obfuscated payloads",
                "technique_id": tech["id"],
                "sample_obfuscated": obfuscated,
            }
            findings.append(finding)

        if not waf_detected:
            findings.append(
                {
                    "id": "no-waf-detected",
                    "title": "No WAF Detected",
                    "description": f"No Web Application Firewall detected on {target}",
                    "severity": Severity.INFO.value,
                    "confidence": Confidence.VERIFIED.value,
                    "category": "redteam.evasion",
                    "evidence": "No WAF signatures found in response headers",
                    "remediation": "Consider adding WAF protection",
                }
            )

        return AgentResult(
            agent_name=self.name,
            status="completed",
            findings=findings,
            summary=f"WAF: {waf_detected or 'None detected'} | {len(EVASION_TECHNIQUES)} evasion techniques available",
            data={"waf_detected": waf_detected, "evasion_techniques": len(EVASION_TECHNIQUES)},
        )
