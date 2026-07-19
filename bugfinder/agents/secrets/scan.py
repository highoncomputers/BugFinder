from __future__ import annotations

import re

import httpx

from bugfinder.agents.base import AgentResult, BaseAgent
from bugfinder.utils.crypto import detect_high_entropy_strings

SECRET_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?i)api[_-]?key\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,64})['\"]?", "API Key", "high"),
    (r"(?i)secret\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{8,64})['\"]?", "Secret Key", "high"),
    (r"(?i)password\s*[=:]\s*['\"]?([^\s'\"\n]{4,})['\"]?", "Password", "critical"),
    (r"(?i)token\s*[=:]\s*['\"]?([A-Za-z0-9_\-\.]{8,})['\"]?", "Token", "high"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token", "critical"),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Access Token", "critical"),
    (r"sk-[A-Za-z0-9]{32,}", "OpenAI API Key", "critical"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "critical"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT Token", "high"),
    (r"-----BEGIN (RSA |EC |DSA |)?PRIVATE KEY-----", "Private Key", "critical"),
]


class SecretsScanAgent(BaseAgent):
    name = "secrets.scan"
    description = "Scan for exposed secrets and credentials"

    async def execute(self) -> AgentResult:
        base_url = self.context.target
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"

        headers = {"User-Agent": "BugFinder/0.1.0"}
        findings = []

        targets_to_scan = [base_url]

        async with httpx.AsyncClient(timeout=30, follow_redirects=True, verify=False) as client:
            js_paths = ["/", "/static/js/", "/assets/", "/app.js", "/main.js"]
            for path in js_paths:
                from urllib.parse import urljoin

                url = urljoin(base_url, path)
                if url not in targets_to_scan:
                    targets_to_scan.append(url)

            for url in targets_to_scan:
                try:
                    resp = await client.get(url, headers=headers)
                    text = resp.text

                    for pattern, name, severity in SECRET_PATTERNS:
                        matches = re.finditer(pattern, text)
                        for match in matches:
                            value = match.group(0)
                            findings.append(
                                {
                                    "title": f"Potential Secret Found: {name}",
                                    "description": f"Found potential {name} in {url}. Value starts with: " + value[:20] + "...",
                                    "severity": severity,
                                    "confidence": "needs_review",
                                    "category": "secret_exposure",
                                    "evidence": {
                                        "url": url,
                                        "pattern": name,
                                        "value_prefix": value[:30],
                                        "position": match.start(),
                                    },
                                }
                            )

                    high_entropy = detect_high_entropy_strings(text)
                    for he in high_entropy:
                        findings.append(
                            {
                                "title": f"High Entropy String Detected: {he['pattern']}",
                                "description": f"Potential secret-like string (entropy: {he['entropy']}) "
                                f"matching pattern '{he['pattern']}' in {url}",
                                "severity": "medium",
                                "confidence": "needs_review",
                                "category": "secret_exposure",
                                "evidence": {
                                    "url": url,
                                    "entropy": he["entropy"],
                                    "pattern": he["pattern"],
                                    "value_prefix": he["value"][:30],
                                },
                            }
                        )

                except Exception:
                    continue

        deduped = {}
        for f in findings:
            key = (f["title"], f["evidence"].get("value_prefix", ""))
            if key not in deduped:
                deduped[key] = f
        findings = list(deduped.values())

        critical = sum(1 for f in findings if f["severity"] == "critical")
        high = sum(1 for f in findings if f["severity"] == "high")
        summary = f"Found {len(findings)} potential secrets ({critical} critical, {high} high)"

        for f in findings:
            f["id"] = f"secret-{findings.index(f)}"

        return AgentResult(
            agent_name=self.name,
            status="completed",
            findings=findings,
            summary=summary,
        )
