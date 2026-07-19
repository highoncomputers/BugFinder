from __future__ import annotations

from bugfinder.agents.base import AgentContext, AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity
from bugfinder.utils.http import get


class CSRFAgent(BaseAgent):
    category = "web"
    name = "csrf"

    async def execute(self, context: AgentContext) -> AgentResult:
        findings = []
        target = context.target
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port:
            base_url += f":{target.port}"

        resp = await get(base_url, timeout=10)
        page_text = resp.text if hasattr(resp, "text") else ""

        forms = self._extract_forms(page_text, base_url)

        for form in forms:
            action = form.get("action", base_url)
            method = form.get("method", "GET").upper()
            fields = form.get("fields", [])

            has_csrf = any(
                "csrf" in f.get("name", "").lower() or "token" in f.get("name", "").lower() or "_token" in f.get("name", "")
                for f in fields
            )

            if method == "POST" and not has_csrf:
                findings.append(
                    {
                        "title": "Missing CSRF Protection",
                        "description": f"Form at {action} uses POST method without CSRF token.",
                        "severity": Severity.HIGH,
                        "confidence": Confidence.MEDIUM,
                        "category": "csrf",
                        "cwe_id": "352",
                        "owasp_category": "A01-Broken Access Control",
                        "cvss_score": 6.5,
                        "evidence": {"form_action": action, "form_fields": fields},
                        "remediation": "Implement anti-CSRF tokens for all state-changing requests. Use SameSite cookies.",
                    }
                )

            # Check for weak CSRF: token in URL params (GET)
            for f in fields:
                if "csrf" in f.get("name", "").lower() and method == "GET":
                    findings.append(
                        {
                            "title": "CSRF Token Exposed in URL",
                            "description": f"CSRF token in form at {action} is sent via GET, exposing it in URLs.",
                            "severity": Severity.MEDIUM,
                            "confidence": Confidence.MEDIUM,
                            "category": "csrf",
                            "cwe_id": "352",
                            "owasp_category": "A01-Broken Access Control",
                            "cvss_score": 4.3,
                            "evidence": {"form_action": action, "token_field": f},
                            "remediation": "Use POST for state-changing requests. CSRF tokens should never appear in URLs.",
                        }
                    )

        return AgentResult(
            agent_name="csrf",
            status="completed",
            findings=findings,
            summary=f"Found {len(findings)} CSRF issues",
        )

    def _extract_forms(self, html: str, base_url: str) -> list[dict]:
        forms = []
        import re

        form_pattern = re.compile(r"<form[^>]*>", re.IGNORECASE)
        input_pattern = re.compile(r"<input[^>]*>", re.IGNORECASE)

        form_matches = list(form_pattern.finditer(html))
        for i, fm in enumerate(form_matches):
            form_tag = fm.group()
            action = ""
            method = "GET"
            action_m = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form_tag, re.IGNORECASE)
            if action_m:
                action = action_m.group(1)
            method_m = re.search(r'method\s*=\s*["\']([^"\']*)["\']', form_tag, re.IGNORECASE)
            if method_m:
                method = method_m.group(1)

            if not action:
                action = base_url

            # Find inputs until next form tag
            end_idx = form_matches[i + 1].start() if i + 1 < len(form_matches) else len(html)
            form_html = html[fm.end() : end_idx]

            fields = []
            for im in input_pattern.finditer(form_html):
                input_tag = im.group()
                name_m = re.search(r'name\s*=\s*["\']([^"\']*)["\']', input_tag, re.IGNORECASE)
                if name_m:
                    fields.append(
                        {"name": name_m.group(1), "type": re.search(r'type\s*=\s*["\']([^"\']*)["\']', input_tag, re.IGNORECASE)}
                    )

            forms.append({"action": action, "method": method, "fields": fields})

        return forms
