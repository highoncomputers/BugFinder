from __future__ import annotations

import json
import logging
from typing import Any

from bugfinder.ai.client import get_ai_client
from bugfinder.core.config import Settings

logger = logging.getLogger(__name__)


class FalsePositiveAnalyzer:
    def __init__(self):
        self.settings = Settings()
        self.client = get_ai_client()

    async def analyze_finding(self, finding: Any, target: str = "") -> dict[str, Any]:
        title = getattr(finding, "title", "") or (isinstance(finding, dict) and finding.get("title", "")) or ""
        description = getattr(finding, "description", "") or (isinstance(finding, dict) and finding.get("description", "")) or ""
        evidence = getattr(finding, "evidence", "") or (isinstance(finding, dict) and finding.get("evidence", "")) or ""
        category = getattr(finding, "category", "") or (isinstance(finding, dict) and finding.get("category", "")) or ""

        if not self.client or not self.settings.ai_enabled:
            return {"is_false_positive": False, "confidence": 0.5, "reason": "AI not available"}

        prompt = f"""You are a security expert analyzing a potential vulnerability finding.
Determine if this finding is likely a false positive.

Target: {target}
Category: {category}
Title: {title}
Description: {description}
Evidence: {json.dumps(evidence) if evidence else "N/A"}

Respond with JSON: {{"is_false_positive": bool, "confidence": float (0-1), "reason": string, "suggested_action": string}}
"""

        try:
            response = await self.client.chat_json(prompt)
            if isinstance(response, dict):
                return response
            return {"is_false_positive": False, "confidence": 0.5, "reason": "Could not parse AI response"}
        except Exception as e:
            logger.error("False positive analysis failed: %s", e)
            return {"is_false_positive": False, "confidence": 0.5, "reason": f"Analysis error: {e}"}

    async def analyze_batch(self, findings: list[Any], target: str = "") -> list[dict[str, Any]]:
        results = []
        for finding in findings:
            result = await self.analyze_finding(finding, target)
            results.append(result)
        return results
