from __future__ import annotations

import json
import logging
from typing import Any, Optional

from bugfinder.ai.client import get_ai_client
from bugfinder.core.config import Settings

logger = logging.getLogger(__name__)


class AIExplainer:
    def __init__(self):
        self.settings = Settings()
        self.client = get_ai_client()

    async def explain_finding(self, finding: Any, audience: str = "beginner") -> dict[str, str]:
        title = getattr(finding, "title", "") or (isinstance(finding, dict) and finding.get("title", "")) or "Unknown"
        description = getattr(finding, "description", "") or (isinstance(finding, dict) and finding.get("description", "")) or ""
        category = getattr(finding, "category", "") or (isinstance(finding, dict) and finding.get("category", "")) or ""
        remediation = getattr(finding, "remediation", "") or (isinstance(finding, dict) and finding.get("remediation", "")) or ""

        if not self.client or not self.settings.ai_enabled:
            return self._template_explanation(title, description, category, remediation, audience)

        prompt = f"""You are a security educator explaining vulnerabilities to a {audience}.

Vulnerability: {title}
Category: {category}
Description: {description}
Remediation: {remediation}

Explain in simple terms:
1. What is this vulnerability? (plain English, no jargon)
2. Why is it dangerous?
3. How was it found?
4. How to fix it?

Respond with JSON: {{"what_it_is": string, "why_dangerous": string, "how_found": string, "how_to_fix": string, "analogy": string}}
"""

        try:
            response = await self.client.chat_json(prompt)
            if isinstance(response, dict):
                return response
        except Exception as e:
            logger.error("AI explanation failed: %s", e)

        return self._template_explanation(title, description, category, remediation, audience)

    def _template_explanation(self, title: str, description: str, category: str,
                               remediation: str, audience: str) -> dict[str, str]:
        if audience == "beginner":
            return {
                "what_it_is": f"{title} is a security issue found in the application.",
                "why_dangerous": description or "This could allow attackers to access sensitive information.",
                "how_found": "BugFinder automatically detected this by sending safe test payloads and analyzing responses.",
                "how_to_fix": remediation or "Apply the recommended fix based on the vulnerability type.",
                "analogy": "Think of it like leaving your front door unlocked - someone might walk in and take things.",
            }
        return {
            "what_it_is": title,
            "why_dangerous": description,
            "how_found": "Automated security scan",
            "how_to_fix": remediation,
            "analogy": "",
        }

    async def explain_batch(self, findings: list[Any], audience: str = "beginner") -> list[dict[str, str]]:
        return [await self.explain_finding(f, audience) for f in findings]
