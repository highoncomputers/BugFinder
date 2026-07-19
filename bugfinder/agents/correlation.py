from __future__ import annotations

from collections import defaultdict
from typing import Any

from bugfinder.agents.base import AgentResult, BaseAgent

CATEGORY_GROUPS: dict[str, list[str]] = {
    "injection": ["sqli", "xss", "ssrf", "lfi", "injection"],
    "auth": ["authentication", "authorization", "session"],
    "secrets": ["secret_exposure", "hardcoded_credentials"],
    "config": ["security_header", "misconfiguration", "tls"],
    "exposure": ["information_disclosure", "exposed_endpoint", "exposed_service"],
}


class CorrelationAgent(BaseAgent):
    name = "correlation"
    description = "Correlate findings and detect attack chains"

    async def execute(self) -> AgentResult:
        kg = self.context.knowledge_graph
        findings = kg.get_nodes_by_type("finding")

        correlated: list[dict[str, Any]] = []
        attack_chains: list[list[str]] = []
        grouped: dict[str, list[dict]] = defaultdict(list)

        for node_id, data in findings:
            cat = data.get("category", "general")
            for group, cats in CATEGORY_GROUPS.items():
                if cat in cats:
                    grouped[group].append({"id": node_id, **data})
                    break
            else:
                grouped["general"].append({"id": node_id, **data})

        for group_name, group_findings in grouped.items():
            if len(group_findings) > 1:
                ids = [f["id"] for f in group_findings]
                correlated.append(
                    {
                        "group": group_name,
                        "count": len(group_findings),
                        "finding_ids": ids,
                        "max_severity": max(
                            (f.get("severity", "info") for f in group_findings),
                            key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s, 99),
                        ),
                    }
                )
                group_node_id = f"correlation-{group_name}"
                kg.add_node(group_node_id, "correlation", group=group_name, count=len(group_findings))
                for fid in ids:
                    kg.add_edge(fid, group_node_id, "correlated_with")

        cat_map = {"secrets": "exposure", "injection": "authentication", "config": "injection"}
        for src_group, dst_group in cat_map.items():
            if src_group in grouped and dst_group in grouped:
                chain = [
                    f"correlation-{src_group}",
                    f"correlation-{dst_group}",
                ]
                attack_chains.append(chain)
                chain_id = f"attack-chain-{len(attack_chains)}"
                kg.add_node(chain_id, "attack_chain", steps=chain)
                kg.add_edge(chain[0], chain[1], "leads_to")

        summary = f"Correlated {len(findings)} findings into {len(correlated)} groups, {len(attack_chains)} attack chains"
        return AgentResult(
            agent_name=self.name,
            status="completed",
            data={"correlated_groups": correlated, "attack_chains": attack_chains},
            summary=summary,
        )
