from __future__ import annotations

from bugfinder.agents.base import AgentContext, AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity
from bugfinder.utils.http import get


class CachePoisonAgent(BaseAgent):
    category = "web"
    name = "cache"

    async def execute(self, context: AgentContext) -> AgentResult:
        findings = []
        target = context.target
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port:
            base_url += f":{target.port}"

        headers_to_check = ["X-Cache", "CF-Cache-Status", "Age", "Cache-Control", "Pragma"]

        # Check caching headers
        resp = await get(base_url, timeout=10)
        cache_headers = {}
        if hasattr(resp, "headers"):
            for h in headers_to_check:
                val = resp.headers.get(h, "")
                if val:
                    cache_headers[h] = val

        if "X-Cache" in cache_headers:
            findings.append(
                {
                    "title": "Web Cache Detected",
                    "description": f"Server uses caching (X-Cache: {cache_headers['X-Cache']}). May be vulnerable to cache poisoning.",
                    "severity": Severity.INFO,
                    "confidence": Confidence.HIGH,
                    "category": "cache",
                    "cwe_id": "524",
                    "owasp_category": "A05-Security Misconfiguration",
                    "cvss_score": 0.0,
                    "evidence": {"cache_headers": cache_headers},
                    "remediation": "Ensure cache keys include all relevant headers. Use Vary header appropriately.",
                }
            )

        # Test cache key injection via Host header
        try:
            resp1 = await get(base_url, headers={"Host": target.hostname}, timeout=10)
            resp2 = await get(base_url, headers={"Host": "evil.com"}, timeout=10)
            if hasattr(resp2, "headers"):
                cache = resp2.headers.get("X-Cache", "")
                if (
                    cache
                    and "hit" in cache.lower()
                    and hasattr(resp1, "text")
                    and hasattr(resp2, "text")
                    and resp1.text != resp2.text
                ):
                    findings.append(
                        {
                            "title": "Cache Key Injection via Host Header",
                            "description": "Different Host headers produce different cached responses, enabling cache poisoning.",
                            "severity": Severity.HIGH,
                            "confidence": Confidence.MEDIUM,
                            "category": "cache",
                            "cwe_id": "444",
                            "owasp_category": "A01-Broken Access Control",
                            "cvss_score": 7.5,
                            "evidence": {"host_header_injection": True},
                            "remediation": "Include Host header in cache keys. Validate Host header against allowlist.",
                        }
                    )
        except Exception:
            pass

        # Check for cache purge if Varnish detected
        if any("varnish" in str(v).lower() for v in cache_headers.values()):
            try:
                resp = await get(base_url, headers={"Host": target.hostname, "X-Forwarded-For": "127.0.0.1"}, timeout=10)
                if hasattr(resp, "headers"):
                    purge_test = resp.headers.get("X-Cache", "")
                    if purge_test:
                        findings.append(
                            {
                                "title": "Varnish Cache Detected",
                                "description": "Varnish cache detected. Test for unauthenticated PURGE method.",
                                "severity": Severity.INFO,
                                "confidence": Confidence.MEDIUM,
                                "category": "cache",
                                "cwe_id": "524",
                                "owasp_category": "A05-Security Misconfiguration",
                                "cvss_score": 0.0,
                                "evidence": {"varnish_test": purge_test},
                                "remediation": "Restrict PURGE requests to trusted IPs. Use ACL for cache management.",
                            }
                        )
            except Exception:
                pass

        return AgentResult(
            agent_name="cache",
            status="completed",
            findings=findings,
            summary=f"Found {len(findings)} cache-related issues",
        )
