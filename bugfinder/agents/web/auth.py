from __future__ import annotations

import re
from urllib.parse import urljoin

import httpx

from bugfinder.agents.base import AgentResult, BaseAgent

LOGIN_FORM_PATTERNS = re.compile(r"<form[^>]*>(.*?)(?:password|passwd|pwd)(.*?)</form>", re.DOTALL | re.IGNORECASE)
AUTH_ENDPOINTS = [
    "/login",
    "/auth",
    "/signin",
    "/sign-up",
    "/register",
    "/forgot-password",
    "/reset-password",
    "/oauth",
    "/api/auth",
    "/api/login",
    "/api/register",
    "/api/v1/auth",
    "/api/v2/auth",
]


class AuthAgent(BaseAgent):
    name = "web.auth"
    description = "Authentication mechanism discovery and analysis"

    async def execute(self) -> AgentResult:
        base_url = self.context.target
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"

        findings = []
        assets = []
        headers = {"User-Agent": "BugFinder/0.1.0"}

        async with httpx.AsyncClient(timeout=30, follow_redirects=True, verify=False) as client:
            try:
                resp = await client.get(base_url, headers=headers)
                html = resp.text
            except Exception:
                return AgentResult(
                    agent_name=self.name,
                    status="completed",
                    summary="Could not fetch target for auth analysis",
                )

            forms = LOGIN_FORM_PATTERNS.findall(html)
            if forms:
                assets.append(
                    {
                        "id": "auth-login-form",
                        "name": f"{base_url}/login",
                        "asset_type": "authentication_method",
                        "value": "Login form detected",
                        "properties": {"method": "form-based", "source": base_url},
                    }
                )
                findings.append(
                    {
                        "title": "Login Form Detected",
                        "description": f"Found {len(forms)} login form(s) on the landing page",
                        "severity": "info",
                        "category": "authentication",
                        "evidence": {"url": base_url, "form_count": len(forms)},
                    }
                )

            for ep in AUTH_ENDPOINTS:
                url = urljoin(base_url, ep)
                try:
                    tr = await client.get(url, headers=headers)
                    if tr.status_code < 400:
                        assets.append(
                            {
                                "id": f"auth-ep-{ep.replace('/', '_')}",
                                "name": url,
                                "asset_type": "authentication_method",
                                "value": f"HTTP {tr.status_code}",
                                "properties": {"path": ep, "status": tr.status_code},
                            }
                        )
                        if tr.status_code == 200:
                            findings.append(
                                {
                                    "title": f"Auth Endpoint Exposed: {ep}",
                                    "description": f"Authentication endpoint accessible at {url}",
                                    "severity": "info" if "register" in ep else "medium",
                                    "category": "authentication",
                                    "evidence": {"url": url, "path": ep, "status": tr.status_code},
                                }
                            )
                except Exception:
                    continue

            set_cookie = resp.headers.get("set-cookie", "")
            if set_cookie:
                if "httponly" not in set_cookie.lower():
                    findings.append(
                        {
                            "title": "Session Cookie Missing HttpOnly Flag",
                            "description": "Cookies set without HttpOnly flag, susceptible to XSS cookie theft",
                            "severity": "medium",
                            "category": "authentication",
                            "evidence": {"set-cookie": set_cookie[:200]},
                        }
                    )
                if "secure" not in set_cookie.lower():
                    findings.append(
                        {
                            "title": "Session Cookie Missing Secure Flag",
                            "description": "Cookies set without Secure flag, may be sent over HTTP",
                            "severity": "medium",
                            "category": "authentication",
                            "evidence": {"set-cookie": set_cookie[:200]},
                        }
                    )
                if "samesite" not in set_cookie.lower():
                    findings.append(
                        {
                            "title": "Session Cookie Missing SameSite Attribute",
                            "description": "Cookies without SameSite attribute may be vulnerable to CSRF",
                            "severity": "low",
                            "category": "authentication",
                            "evidence": {"set-cookie": set_cookie[:200]},
                        }
                    )

        for f in findings:
            f["id"] = f"auth-finding-{findings.index(f)}"
        summary = f"Analyzed auth on {base_url}, {len(findings)} findings"
        return AgentResult(
            agent_name=self.name,
            status="completed",
            assets=assets,
            findings=findings,
            summary=summary,
        )
