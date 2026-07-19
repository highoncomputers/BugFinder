from __future__ import annotations

import base64
import json

from bugfinder.agents.base import AgentContext, AgentResult, BaseAgent
from bugfinder.core.types import Confidence, Severity
from bugfinder.utils.http import get


class JWTAgent(BaseAgent):
    category = "web"
    name = "jwt"

    async def execute(self, context: AgentContext) -> AgentResult:
        findings = []
        target = context.target
        base_url = f"{target.scheme}://{target.hostname}"
        if target.port:
            base_url += f":{target.port}"

        resp = await get(base_url, timeout=10)
        set_cookie = ""
        if hasattr(resp, "headers"):
            set_cookie = resp.headers.get("Set-Cookie", "") or resp.headers.get("set-cookie", "")

        auth_header = ""
        if hasattr(resp, "request") and hasattr(resp.request, "headers"):
            auth_header = resp.request.headers.get("Authorization", "")

        jwt_token = ""
        if "jwt" in set_cookie.lower():
            import re

            match = re.search(r"=[^;]+\.[^;]+\.[^;]+", set_cookie)
            if match:
                jwt_token = match.group(0)[1:]
        elif auth_header.startswith("Bearer "):
            jwt_token = auth_header[7:]

        if jwt_token:
            parts = jwt_token.split(".")
            if len(parts) == 3:
                try:
                    header_b64 = parts[0]
                    header_b64 += "=" * (4 - len(header_b64) % 4)
                    header = json.loads(base64.urlsafe_b64decode(header_b64))
                    alg = header.get("alg", "")

                    if alg == "none":
                        findings.append(
                            {
                                "title": "JWT 'none' Algorithm Allowed",
                                "description": "The server accepts JWTs with 'none' algorithm, allowing signature bypass.",
                                "severity": Severity.CRITICAL,
                                "confidence": Confidence.HIGH,
                                "category": "jwt",
                                "cwe_id": "345",
                                "owasp_category": "A02-Cryptographic Failures",
                                "cvss_score": 9.1,
                                "evidence": {"algorithm": "none", "header": header},
                                "remediation": "Reject tokens with 'none' algorithm. Always verify signature.",
                            }
                        )
                    elif alg == "HS256":
                        payload_b64 = parts[1]
                        payload_b64 += "=" * (4 - len(payload_b64) % 4)
                        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                        weak_secrets = ["secret", "password", "key", "123456", "changeme", "admin"]
                        for weak_secret in weak_secrets:
                            import hmac

                            sig = hmac.new(weak_secret.encode(), f"{parts[0]}.{parts[1]}".encode(), "sha256").digest()
                            sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
                            if sig_b64 == parts[2]:
                                findings.append(
                                    {
                                        "title": "JWT Weak Secret Key",
                                        "description": f"JWT signed with weak HMAC secret: '{weak_secret}'",
                                        "severity": Severity.CRITICAL,
                                        "confidence": Confidence.HIGH,
                                        "category": "jwt",
                                        "cwe_id": "798",
                                        "owasp_category": "A02-Cryptographic Failures",
                                        "cvss_score": 8.6,
                                        "evidence": {"algorithm": alg, "weak_secret": weak_secret, "payload": payload},
                                        "remediation": "Use a strong, randomly generated secret key of at least 256 bits.",
                                    }
                                )
                                break

                    if "kid" in header:
                        if header["kid"] == "" or ".." in str(header["kid"]) or "/" in str(header["kid"]):
                            findings.append(
                                {
                                    "title": "JWT Key ID (KID) Injection Possible",
                                    "description": "KID header may be vulnerable to path traversal or SQL injection.",
                                    "severity": Severity.HIGH,
                                    "confidence": Confidence.MEDIUM,
                                    "category": "jwt",
                                    "cwe_id": "345",
                                    "owasp_category": "A02-Cryptographic Failures",
                                    "cvss_score": 7.5,
                                    "evidence": {"kid": header.get("kid")},
                                    "remediation": "Validate KID against allowlist, do not use it for file system access.",
                                }
                            )
                except Exception:
                    pass

        return AgentResult(
            agent_name="jwt",
            status="completed",
            findings=findings,
            summary=f"Found {len(findings)} JWT issues",
        )
