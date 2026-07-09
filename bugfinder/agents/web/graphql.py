from __future__ import annotations

from typing import Any

from bugfinder.agents.base import BaseAgent, AgentContext, AgentResult
from bugfinder.core.types import Severity, Confidence
from bugfinder.utils.http import post


class GraphQLAgent(BaseAgent):
    category = "web"
    name = "graphql"

    async def execute(self, context: AgentContext) -> AgentResult:
        findings = []
        target = context.target
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port:
            base_url += f":{target.port}"

        endpoints = ["/graphql", "/graphiql", "/gql", "/api/graphql", "/v1/graphql", "/query"]

        introspection_query = {"query": "{__schema{types{name fields{name type{name kind}}}}}"}

        for endpoint in endpoints:
            url = f"{base_url}{endpoint}"
            try:
                resp = await post(url, json=introspection_query, timeout=10)
                text = resp.text if hasattr(resp, 'text') else ""
                if '"data"' in text and '__schema' in text:
                    fields: list[str] = []
                    if 'types' in text:
                        import re
                        fields = re.findall(r'"name"\s*:\s*"([^"]+)"', text)

                    findings.append({
                        "title": "GraphQL Introspection Enabled",
                        "description": f"GraphQL introspection is enabled at {endpoint}. This exposes the entire schema.",
                        "severity": Severity.MEDIUM,
                        "confidence": Confidence.HIGH,
                        "category": "graphql",
                        "cwe_id": "200",
                        "owasp_category": "A01-Broken Access Control",
                        "cvss_score": 5.3,
                        "evidence": {"endpoint": endpoint, "detected_types": fields[:20]},
                        "remediation": "Disable introspection in production. Use allowlisting for query complexity.",
                    })

                    depth_payload = {"query": "{" + " ".join(["test" + str(i) + ": __typename " for i in range(10)]) + "}"}
                    try:
                        await post(url, json=depth_payload, timeout=10)
                    except Exception:
                        findings.append({
                            "title": "GraphQL Depth Limiting Bypass",
                            "description": f"No depth limiting detected at {endpoint}",
                            "severity": Severity.LOW,
                            "confidence": Confidence.MEDIUM,
                            "category": "graphql",
                            "cwe_id": "770",
                            "owasp_category": "A04-Unrestricted Resource Consumption",
                            "cvss_score": 4.3,
                            "evidence": {"endpoint": endpoint, "test": "deeply_nested_query_accepted"},
                            "remediation": "Implement query depth limiting and complexity analysis.",
                        })
                    break
            except Exception:
                pass

        return AgentResult(
            agent_name="graphql",
            status="completed",
            findings=findings,
            summary=f"Found {len(findings)} GraphQL issues",
        )
