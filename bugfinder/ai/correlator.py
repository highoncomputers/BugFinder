from __future__ import annotations

import json
import logging
from typing import Any, Optional

from bugfinder.ai.client import get_ai_client
from bugfinder.core.config import Settings

logger = logging.getLogger(__name__)


class FindingCorrelator:
    def __init__(self):
        self.settings = Settings()
        self.client = get_ai_client()

    async def correlate_findings(self, findings: list[Any]) -> list[dict[str, Any]]:
        if len(findings) < 2:
            return []

        finding_summaries = []
        for f in findings:
            title = getattr(f, "title", "") or (isinstance(f, dict) and f.get("title", ""))
            category = getattr(f, "category", "") or (isinstance(f, dict) and f.get("category", ""))
            severity = str(getattr(f, "severity", "")) or (isinstance(f, dict) and str(f.get("severity", "")))
            finding_summaries.append({"title": title, "category": category, "severity": severity})

        if not self.client or not self.settings.ai_enabled:
            return self._rule_based_correlation(finding_summaries)

        prompt = f"""Analyze these security findings and identify:
1. Which findings are related (part of same attack chain)
2. The attack chain flow
3. Priority order for remediation

Findings: {json.dumps(finding_summaries, indent=2)}

Respond with JSON: {{"chains": [{{"chain_id": int, "name": string, "findings": [indices], "flow_description": string, "remediation_priority": int}}]}}
"""

        try:
            response = await self.client.chat_json(prompt)
            if isinstance(response, dict) and "chains" in response:
                return response["chains"]
        except Exception as e:
            logger.error("AI correlation failed: %s", e)

        return self._rule_based_correlation(finding_summaries)

    def _rule_based_correlation(self, findings: list[dict]) -> list[dict[str, Any]]:
        injection_findings = [i for i, f in enumerate(findings) if f.get("category", "").lower() in ("xss", "sqli", "ssti", "lfi", "ssrf")]
        auth_findings = [i for i, f in enumerate(findings) if f.get("category", "").lower() in ("auth", "jwt", "cors", "csrf")]
        config_findings = [i for i, f in enumerate(findings) if f.get("category", "").lower() in ("secrets", "config", "exposure")]
        recon_findings = [i for i, f in enumerate(findings) if f.get("category", "").lower() in ("recon", "info")]

        chains = []
        if injection_findings:
            chains.append({
                "chain_id": 1,
                "name": "Injection Attack Chain",
                "findings": injection_findings,
                "flow_description": "Injection vulnerabilities that could be chained for code execution or data extraction",
                "remediation_priority": 1,
            })
        if auth_findings:
            chains.append({
                "chain_id": 2,
                "name": "Authentication Bypass Chain",
                "findings": auth_findings,
                "flow_description": "Authentication and authorization weaknesses that could lead to account takeover",
                "remediation_priority": 2,
            })
        if config_findings:
            chains.append({
                "chain_id": 3,
                "name": "Information Disclosure Chain",
                "findings": config_findings,
                "flow_description": "Exposed secrets and misconfigurations that aid further attacks",
                "remediation_priority": 3,
            })
        if recon_findings:
            chains.append({
                "chain_id": 4,
                "name": "Reconnaissance Findings",
                "findings": recon_findings,
                "flow_description": "Information gathering results that provide context for exploitation",
                "remediation_priority": 4,
            })
        return chains

    async def build_attack_graph(self, chains: list[dict]) -> dict[str, Any]:
        graph: dict[str, Any] = {"nodes": [], "edges": []}
        for chain in chains:
            chain_node = {
                "id": f"chain_{chain['chain_id']}",
                "label": chain["name"],
                "type": "chain",
                "priority": chain["remediation_priority"],
            }
            graph["nodes"].append(chain_node)
            prev_node = None
            for idx in chain.get("findings", []):
                node = {
                    "id": f"finding_{idx}",
                    "label": chain.get("flow_description", "")[:50],
                    "type": "finding",
                }
                graph["nodes"].append(node)
                if prev_node:
                    graph["edges"].append({"from": prev_node, "to": node["id"], "label": "leads_to"})
                graph["edges"].append({"from": chain_node["id"], "to": node["id"], "label": "contains"})
                prev_node = node["id"]
        return graph
