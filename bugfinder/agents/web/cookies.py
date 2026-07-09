from __future__ import annotations

from typing import Any

from bugfinder.agents.base import BaseAgent, AgentContext, AgentResult
from bugfinder.core.types import Severity, Confidence
from bugfinder.utils.http import get


class CookieSecurityAgent(BaseAgent):
    category = "web"
    name = "cookies"

    async def execute(self, context: AgentContext) -> AgentResult:
        findings = []
        target = context.target
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port:
            base_url += f":{target.port}"

        resp = await get(base_url, timeout=10)
        cookies = []
        if hasattr(resp, 'headers'):
            raw_cookies = resp.headers.get_list("Set-Cookie") if hasattr(resp.headers, 'get_list') else []
            if not raw_cookies:
                set_cookie = resp.headers.get("Set-Cookie", "")
                if set_cookie:
                    raw_cookies = [set_cookie]
            for cookie_str in raw_cookies:
                cookies.append(cookie_str)

        if not cookies:
            return AgentResult(
                agent_name="cookies",
                status="completed",
                findings=[],
                summary="No cookies to analyze",
            )

        for cookie_str in cookies:
            cookie_name = cookie_str.split("=")[0] if "=" in cookie_str else cookie_str
            parts = cookie_str.lower()

            flags = {
                "httponly": "httponly" in parts,
                "secure": "secure" in parts,
                "samesite_lax": "samesite=lax" in parts,
                "samesite_strict": "samesite=strict" in parts,
                "samesite_none": "samesite=none" in parts,
            }

            if not flags["httponly"]:
                findings.append({
                    "title": "Cookie Missing HttpOnly Flag",
                    "description": f"Cookie '{cookie_name}' is missing HttpOnly flag, accessible via JavaScript.",
                    "severity": Severity.MEDIUM,
                    "confidence": Confidence.HIGH,
                    "category": "cookies",
                    "cwe_id": "1004",
                    "owasp_category": "A04-Insecure Design",
                    "cvss_score": 5.3,
                    "evidence": {"cookie": cookie_str},
                    "remediation": "Set HttpOnly flag on cookies that don't need JavaScript access.",
                })

            if not flags["secure"]:
                findings.append({
                    "title": "Cookie Missing Secure Flag",
                    "description": f"Cookie '{cookie_name}' is missing Secure flag, can be sent over HTTP.",
                    "severity": Severity.MEDIUM,
                    "confidence": Confidence.HIGH,
                    "category": "cookies",
                    "cwe_id": "614",
                    "owasp_category": "A02-Cryptographic Failures",
                    "cvss_score": 5.3,
                    "evidence": {"cookie": cookie_str},
                    "remediation": "Set Secure flag on all cookies to restrict transmission to HTTPS.",
                })

            # Session-like cookie without SameSite
            if any(s in cookie_name.lower() for s in ["session", "token", "sid", "auth", "jwt"]):
                if not flags["samesite_lax"] and not flags["samesite_strict"]:
                    findings.append({
                        "title": "Session Cookie Missing SameSite Attribute",
                        "description": f"Session cookie '{cookie_name}' is missing SameSite flag.",
                        "severity": Severity.LOW,
                        "confidence": Confidence.MEDIUM,
                        "category": "cookies",
                        "cwe_id": "1275",
                        "owasp_category": "A01-Broken Access Control",
                        "cvss_score": 3.1,
                        "evidence": {"cookie": cookie_str},
                        "remediation": "Set SameSite=Lax or SameSite=Strict for session cookies.",
                    })

        return AgentResult(
            agent_name="cookies",
            status="completed",
            findings=findings,
            summary=f"Analyzed {len(cookies)} cookies, found {len(findings)} issues",
        )
