from __future__ import annotations

import httpx

from bugfinder.agents.base import AgentResult, BaseAgent

TECH_SIGNATURES: dict[str, list[str]] = {
    "nginx": ["nginx", "nginx/"],
    "apache": ["apache", "apache/", "httpd"],
    "cloudflare": ["cloudflare"],
    "wordpress": ["wp-content", "wp-includes", "wordpress"],
    "django": ["django", "csrftoken", "sessionid"],
    "laravel": ["laravel", "livewire"],
    "react": ["react", "reactjs", "__nextreact"],
    "nextjs": ["next.js", "__next", "_next/static"],
    "vue": ["vue.js", "vuejs"],
    "angular": ["angular", "ng-"],
    "express": ["express", "connect.sid"],
    "fastapi": ["fastapi"],
    "flask": ["flask", "flaskr"],
    "graphql": ["graphql"],
    "jquery": ["jquery"],
    "bootstrap": ["bootstrap"],
    "tailwind": ["tailwind"],
}


class TechDetectAgent(BaseAgent):
    name = "recon.tech"
    description = "Web technology fingerprinting"

    async def execute(self) -> AgentResult:
        url = self.context.target
        if not url.startswith("http"):
            url = f"https://{url}"

        headers = {"User-Agent": "BugFinder/0.1.0"}
        technologies = []
        findings = []

        try:
            async with httpx.AsyncClient(timeout=30, follow_redirects=True, verify=False) as client:
                response = await client.get(url, headers=headers)
                body = response.text.lower()
                raw_headers = dict(response.headers)
                header_str = str(raw_headers).lower()

                server = raw_headers.get("server", "")
                if server:
                    technologies.append(
                        {
                            "id": f"server-{server}",
                            "name": server,
                            "asset_type": "technology",
                            "properties": {"source": "http-server-header", "version": server},
                        }
                    )

                for tech, patterns in TECH_SIGNATURES.items():
                    for pattern in patterns:
                        if pattern in body or pattern in header_str:
                            technologies.append(
                                {
                                    "id": f"tech-{tech}",
                                    "name": tech,
                                    "asset_type": "technology",
                                    "properties": {"source": "fingerprint"},
                                }
                            )
                            break

                csp = raw_headers.get("content-security-policy", "")
                if csp:
                    findings.append(
                        {
                            "title": "Content Security Policy Header Found",
                            "description": f"CSP: {csp[:100]}...",
                            "severity": "info",
                            "category": "security_header",
                            "evidence": {"header": "content-security-policy", "value": csp[:200]},
                        }
                    )

                if "x-frame-options" not in raw_headers:
                    findings.append(
                        {
                            "title": "Missing X-Frame-Options Header",
                            "description": (
                                "The X-Frame-Options header is not set, making the site vulnerable to clickjacking"
                            ),
                            "severity": "medium",
                            "category": "security_header",
                            "evidence": {"url": url, "missing_header": "X-Frame-Options"},
                        }
                    )

                if "strict-transport-security" not in raw_headers:
                    findings.append(
                        {
                            "title": "Missing HSTS Header",
                            "description": "HTTP Strict-Transport-Security header is not set",
                            "severity": "low",
                            "category": "security_header",
                            "evidence": {"url": url, "missing_header": "Strict-Transport-Security"},
                        }
                    )

        except Exception as e:
            return AgentResult(
                agent_name=self.name,
                status="completed",
                summary=f"Tech detection failed: {e}",
            )

        for f in findings:
            f["id"] = f"tech-finding-{len(findings)}"

        tech_names = [t["name"] for t in technologies]
        summary = f"Detected {len(technologies)} technologies: {', '.join(tech_names[:5])}"
        if len(tech_names) > 5:
            summary += f" +{len(tech_names) - 5} more"

        return AgentResult(
            agent_name=self.name,
            status="completed",
            assets=technologies,
            findings=findings,
            summary=summary,
        )
