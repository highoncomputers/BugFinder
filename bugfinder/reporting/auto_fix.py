from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FixSuggestion:
    title: str
    description: str
    severity: str
    code_fixes: list[dict[str, str]] = field(default_factory=list)
    config_fixes: list[dict[str, str]] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


FIX_GENERATORS: dict[str, Any] = {}


def _register(category: str):
    def decorator(func):
        FIX_GENERATORS[category] = func
        return func
    return decorator


def generate_fix(finding: dict[str, Any] | Any) -> FixSuggestion | None:
    category = ""
    title = ""
    severity = "medium"

    if hasattr(finding, "category"):
        category = (finding.category or "").lower().replace(" ", "-").replace("_", "-")
        title = finding.title or ""
        severity = getattr(finding, "severity", "medium")
        if hasattr(severity, "value"):
            severity = severity.value
    elif isinstance(finding, dict):
        category = (finding.get("category", "") or "").lower().replace(" ", "-").replace("_", "-")
        title = finding.get("title", "")
        severity = finding.get("severity", "medium")

    generator = FIX_GENERATORS.get(category)
    if generator:
        return generator(title, severity)
    return _generic_fix(title, severity, category)


def generate_fixes_for_finding(finding: Any) -> list[dict[str, Any]]:
    fix = generate_fix(finding)
    if not fix:
        return []
    return [{
        "title": fix.title,
        "description": fix.description,
        "severity": fix.severity,
        "code_fixes": fix.code_fixes,
        "config_fixes": fix.config_fixes,
        "references": fix.references,
    }]


@_register("xss")
def _xss_fix(title: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Cross-Site Scripting (XSS) Remediation",
        description="Apply output encoding, Content-Security-Policy headers, and input validation.",
        severity=severity,
        code_fixes=[
            {
                "language": "python",
                "label": "Output Encoding (Flask/Jinja2)",
                "code": """from markupsafe import escape

# Always escape user input in templates
safe_output = escape(user_input)
# Or use Jinja2 autoescaping (enabled by default in Flask)
# {{ user_input | e }}  # explicit escaping
# {{ user_input }}      # auto-escaped in Flask""",
            },
            {
                "language": "python",
                "label": "Output Encoding (Django)",
                "code": """from django.utils.html import escape
from django.template.defaultfilters import safe

# Always escape in views
safe_output = escape(request.POST.get('input', ''))
# In templates use |escape filter (default)
# {{ value|escape }}
# For safe HTML use mark_safe() only on trusted content""",
            },
            {
                "language": "javascript",
                "label": "DOM-based XSS Prevention",
                "code": """// Never use innerHTML with user input
// SAFE:
document.getElementById('output').textContent = userInput;
// Or use createTextNode:
const node = document.createTextNode(userInput);
document.getElementById('output').appendChild(node);

// If HTML is needed, sanitize first:
function sanitize(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
}""",
            },
            {
                "language": "html",
                "label": "CSP Header (Meta Tag)",
                "code": """<!-- Content-Security-Policy via meta tag -->
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self';
               script-src 'self';
               style-src 'self' 'unsafe-inline';
               img-src 'self' data:;">""",
            },
        ],
        config_fixes=[
            {
                "title": "CSP Header (Nginx)",
                "code": """add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';" always;""",
            },
            {
                "title": "CSP Header (Apache)",
                "code": """Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';" """,
            },
        ],
        references=[
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    )


@_register("sqli")
def _sqli_fix(title: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="SQL Injection Remediation",
        description="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
        severity=severity,
        code_fixes=[
            {
                "language": "python",
                "label": "Parameterized Query (SQLAlchemy)",
                "code": """# UNSAFE: f"SELECT * FROM users WHERE id = {user_id}"
# SAFE - parameterized:
from sqlalchemy import text

query = text("SELECT * FROM users WHERE id = :user_id")
result = session.execute(query, {"user_id": user_id})

# Or using ORM:
user = session.query(User).filter(User.id == user_id).first()""",
            },
            {
                "language": "python",
                "label": "Parameterized Query (psycopg2)",
                "code": """import psycopg2

# UNSAFE: f"SELECT * FROM users WHERE name = '{name}'"
# SAFE:
cur.execute("SELECT * FROM users WHERE name = %s", (name,))""",
            },
            {
                "language": "python",
                "label": "Parameterized Query (sqlite3)",
                "code": """import sqlite3

# UNSAFE: f"SELECT * FROM users WHERE id = {id}"
# SAFE:
cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))""",
            },
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    )


@_register("ssrf")
def _ssrf_fix(title: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Server-Side Request Forgery (SSRF) Remediation",
        description="Validate and restrict URLs. Use an allowlist of permitted hosts.",
        severity=severity,
        code_fixes=[
            {
                "language": "python",
                "label": "URL Allowlist Validation",
                "code": """from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}
BLOCKED_IPS = {"169.254.169.254", "127.0.0.1", "0.0.0.0", "::1"}
BLOCKED_SCHEMES = {"file:", "gopher:", "dict:"}

def safe_fetch(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    scheme = parsed.scheme

    if scheme in BLOCKED_SCHEMES:
        raise ValueError(f"Blocked scheme: {scheme}")
    if host not in ALLOWED_HOSTS:
        raise ValueError(f"Host not allowed: {host}")

    # Resolve and check for internal IPs
    import socket
    try:
        ip = socket.gethostbyname(host)
        if ip.startswith(("10.", "172.16.", "192.168.")):
            raise ValueError("Internal IP blocked")
    except socket.gaierror:
        raise ValueError("Could not resolve host")

    return url""",
            },
            {
                "language": "python",
                "label": "Disable Redirects",
                "code": """import httpx

# SSRF protection: never follow redirects blindly
async with httpx.AsyncClient(follow_redirects=False) as client:
    resp = await client.get(url, timeout=5)
    # Validate redirect target if 3xx
    if 300 <= resp.status_code < 400:
        target = resp.headers.get("location", "")
        if target and not target.startswith(ALLOWED_HOSTS):
            raise ValueError("Redirect to untrusted host")""",
            },
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/918.html",
        ],
    )


@_register("lfi")
def _lfi_fix(title: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Local File Inclusion (LFI) Remediation",
        description="Validate file paths, use a whitelist, and strip directory traversal sequences.",
        severity=severity,
        code_fixes=[
            {
                "language": "python",
                "label": "Path Traversal Prevention",
                "code": """import os
from pathlib import Path

ALLOWED_DIR = Path("/var/www/files/")
ALLOWED_FILES = {"report1.pdf", "report2.pdf", "logo.png"}

def safe_read_file(filename: str) -> bytes:
    # Method 1: Allowlist
    if filename not in ALLOWED_FILES:
        raise ValueError("File not allowed")

    # Method 2: Path sanitization
    safe_path = ALLOWED_DIR / Path(filename).name
    safe_path = safe_path.resolve()

    if not str(safe_path).startswith(str(ALLOWED_DIR.resolve())):
        raise ValueError("Path traversal detected")

    return safe_path.read_bytes()""",
            },
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/98.html",
        ],
    )


@_register("ssti")
def _ssti_fix(title: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Server-Side Template Injection (SSTI) Remediation",
        description="Sandbox template environments, disable access to dangerous objects, auto-escape.",
        severity=severity,
        code_fixes=[
            {
                "language": "python",
                "label": "Jinja2 Sandbox",
                "code": """from jinja2 import Environment, BaseLoader, TemplateNotFound
from jinja2.sandbox import SandboxedEnvironment

# UNSAFE:
# template = Template("Hello {{ name }}")
# output = template.render(name=user_input)

# SAFE - sandboxed with restricted access:
env = SandboxedEnvironment(loader=BaseLoader())
# Only allow limited builtins
env.globals.clear()
env.globals.update({
    "str": str,
    "int": int,
    "list": list,
    "dict": dict,
})

template = env.from_string("Hello {{ name }}")
output = template.render(name=user_input)""",
            },
            {
                "language": "python",
                "label": "Disable Access to Attributes",
                "code": """from jinja2 import Environment, BaseLoader
from jinja2.sandbox import SandboxedEnvironment

# Restrict attribute access
env = SandboxedEnvironment(
    loader=BaseLoader(),
    autoescape=True,
)
# Deny dangerous attributes
DENIED = ['__class__', '__base__', '__subclasses__',
          '__globals__', '__builtins__', '__init__',
          '__mro__', '__bases__']""",
            },
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Template_Injection_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/1336.html",
        ],
    )


@_register("jwt")
def _jwt_fix(title: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="JWT Security Remediation",
        description="Validate algorithm, use strong secrets, set short expiry, validate all claims.",
        severity=severity,
        code_fixes=[
            {
                "language": "python",
                "label": "Secure JWT Validation",
                "code": """import jwt
from jwt import PyJWTError

JWT_SECRET = "your-strong-secret-at-least-256-bits"
JWT_ALGORITHM = "HS256"  # Never allow 'none' algorithm

def verify_jwt(token: str) -> dict:
    try:
        # Explicitly restrict allowed algorithms
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={
                "verify_signature": True,
                "verify_exp": True,
                "require": ["exp", "iat"],
            },
        )
        return payload
    except PyJWTError as e:
        raise ValueError(f"Invalid token: {e}")

# UNSAFE: jwt.decode(token, verify=False)""",
            },
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/345.html",
        ],
    )


@_register("cors")
def _cors_fix(title: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="CORS Misconfiguration Remediation",
        description="Restrict Access-Control-Allow-Origin to specific trusted origins.",
        severity=severity,
        config_fixes=[
            {
                "title": "CORS (Nginx)",
                "code": """# Restrict to specific origins
set $cors_origin "";
if ($http_origin ~* (https://example\\.com|https://app\\.example\\.com)) {
    set $cors_origin $http_origin;
}
add_header Access-Control-Allow-Origin $cors_origin always;
add_header Access-Control-Allow-Methods "GET, POST, OPTIONS";
add_header Access-Control-Allow-Credentials "true";
add_header Access-Control-Max-Age 3600;""",
            },
            {
                "title": "CORS (FastAPI/Python)",
                "code": """from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=[  # Specific, not ["*"]
        "https://example.com",
        "https://app.example.com",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)""",
            },
        ],
        references=[
            "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny/",
            "https://cwe.mitre.org/data/definitions/942.html",
        ],
    )


@_register("csrf")
def _csrf_fix(title: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="CSRF Remediation",
        description="Use CSRF tokens, SameSite cookies, and custom headers.",
        severity=severity,
        code_fixes=[
            {
                "language": "python",
                "label": "CSRF Protection (Flask)",
                "code": """from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

# In templates:
# <form method="post">
#     <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
# </form>""",
            },
            {
                "language": "python",
                "label": "CSRF Protection (Django)",
                "code": """# Django includes CSRF by default
# Ensure it's enabled in settings:
INSTALLED_APPS = [
    'django.middleware.csrf.CsrfViewMiddleware',
    # ...
]

# In templates use {% csrf_token %}
# For AJAX, include X-CSRFToken header""",
            },
        ],
        config_fixes=[
            {
                "title": "SameSite Cookie Attribute",
                "code": """# Set SameSite=Lax or Strict on session cookies
Set-Cookie: session=...; SameSite=Lax; Secure; HttpOnly""",
            },
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/352.html",
        ],
    )


@_register("cookies")
def _cookies_fix(title: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Insecure Cookies Remediation",
        description="Set Secure, HttpOnly, and SameSite flags on all cookies.",
        severity=severity,
        code_fixes=[
            {
                "language": "python",
                "label": "Secure Cookie Flags (FastAPI)",
                "code": """response.set_cookie(
    key="session",
    value=token,
    httponly=True,      # Not accessible via JavaScript
    secure=True,        # HTTPS only
    samesite="lax",     # CSRF protection
    max_age=3600,       # 1 hour
)""",
            },
            {
                "language": "python",
                "label": "Secure Cookie Flags (Flask)",
                "code": """app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_NAME='__Host-session',  # Prefix for additional security
)""",
            },
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        ],
    )


@_register("open-redirect")
@_register("redirect")
def _redirect_fix(title: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Open Redirect Remediation",
        description="Use an allowlist of valid redirect targets. Never redirect to user-supplied URLs directly.",
        severity=severity,
        code_fixes=[
            {
                "language": "python",
                "label": "Redirect Allowlist",
                "code": """from urllib.parse import urlparse

ALLOWED_REDIRECTS = {
    "/dashboard",
    "/profile",
    "/settings",
}

def safe_redirect(url: str) -> str:
    # Option 1: Only allow relative paths
    if url.startswith("/") and not url.startswith("//"):
        if url in ALLOWED_REDIRECTS:
            return url

    # Option 2: Validate against allowlist
    allowed_hosts = {"example.com", "app.example.com"}
    parsed = urlparse(url)
    if parsed.hostname in allowed_hosts:
        return url

    # Fallback to safe default
    return "/dashboard"
""",
            },
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/601.html",
        ],
    )


@_register("host-header")
def _host_header_fix(title: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Host Header Injection Remediation",
        description="Validate the Host header against an allowlist. Don't use Host header to generate URLs.",
        severity=severity,
        code_fixes=[
            {
                "language": "python",
                "label": "Host Header Validation",
                "code": """VALID_HOSTS = {"example.com", "www.example.com", "api.example.com"}

def validate_host(host: str) -> str:
    if host not in VALID_HOSTS:
        return "example.com"  # Safe default
    return host

# Always use trusted host for URL generation:
from django.contrib.sites.models import Site

# SAFE:
domain = Site.objects.get_current().domain
full_url = f"https://{domain}{path}"

# UNSAFE:
# full_url = f"https://{request.headers['host']}{path}" """,
            },
        ],
        config_fixes=[
            {
                "title": "Nginx Host Validation",
                "code": """# Only accept requests with valid Host headers
if ($host !~* ^(example\.com|www\.example\.com)$) {
    return 444;
}

# Or use server_name:
server {
    server_name example.com www.example.com;
    # Requests with other Host headers will be caught by default server block
}""",
            },
        ],
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection/",
        ],
    )


@_register("xxe")
def _xxe_fix(title: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="XXE (XML External Entity) Remediation",
        description="Disable external entity processing in XML parsers.",
        severity=severity,
        code_fixes=[
            {
                "language": "python",
                "label": "Disable XXE (lxml)",
                "code": """from lxml import etree

parser = etree.XMLParser(
    resolve_entities=False,   # Disable entity resolution
    no_network=True,          # Prevent network access
    dtd_validation=False,    # Don't validate DTDs
)
tree = etree.fromstring(xml_data, parser)""",
            },
            {
                "language": "python",
                "label": "Disable XXE (xml.etree)",
                "code": """import defusedxml.ElementTree as ET

# SAFE - use defusedxml instead of xml.etree
tree = ET.fromstring(xml_data)

# defusedxml protects against:
# - Billion laughs attack
# - Quadratic blowup
# - External entity expansion""",
            },
            {
                "language": "python",
                "label": "Disable XXE (lxml - secure defaults)",
                "code": """from lxml import etree

# Most secure configuration:
parser = etree.XMLParser(
    no_network=True,
    resolve_entities=False,
    huge_tree=False,
)
# Or simply use etree.fromstring with default parser
# after disabling DTD loading:
etree.set_default_parser(parser)""",
            },
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/611.html",
        ],
    )


@_register("cache")
def _cache_fix(title: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Cache Poisoning Remediation",
        description="Use cache keys based on all input sources. Validate headers and set no-cache for sensitive content.",
        severity=severity,
        config_fixes=[
            {
                "title": "Cache Headers (Nginx)",
                "code": """# Don't cache sensitive responses
location /api/ {
    add_header Cache-Control "no-store, no-cache, must-revalidate";
    proxy_no_cache 1;
    proxy_cache_bypass 1;
}

# Include all relevant headers in cache key
proxy_cache_key "$scheme$request_method$host$request_uri$http_accept$http_accept_language";""",
            },
            {
                "language": "python",
                "label": "Cache Key Validation",
                "code": """# Never use X-Forwarded-Host or X-Forwarded-Proto
# in cache keys without validation:

VALID_HEADERS = {"accept", "accept-language", "content-type"}

def get_cache_key(request):
    # Only use validated headers
    parts = [request.method, request.path]
    for header in VALID_HEADERS:
        value = request.headers.get(header, "")
        if value:
            parts.append(f"{header}:{value}")
    return ":".join(parts)""",
            },
        ],
        references=[
            "https://owasp.org/www-community/attacks/Cache_Poisoning",
        ],
    )


@_register("race-condition")
def _race_fix(title: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Race Condition Remediation",
        description="Use database-level locks, atomic operations, or transaction isolation.",
        severity=severity,
        code_fixes=[
            {
                "language": "python",
                "label": "Atomic Operations with Lock",
                "code": """import asyncio
from contextlib import asynccontextmanager

class AtomicCounter:
    def __init__(self):
        self._lock = asyncio.Lock()
        self._value = 0

    async def increment(self) -> int:
        async with self._lock:
            current = self._value
            await asyncio.sleep(0)  # Simulate work
            self._value = current + 1
            return self._value

# Or use DB-level locking:
# BEGIN;
# SELECT quantity FROM products WHERE id = 1 FOR UPDATE;
# UPDATE products SET quantity = quantity - 1 WHERE id = 1;
# COMMIT;""",
            },
            {
                "language": "python",
                "label": "Optimistic Locking (SQLAlchemy)",
                "code": """from sqlalchemy import Column, Integer, String, VersionGenerator

class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True)
    balance = Column(Integer, default=0)
    version = Column(Integer, default=1)

# Update with version check:
# UPDATE accounts SET balance = balance - 100, version = version + 1
# WHERE id = 1 AND version = 1
# If 0 rows affected, a concurrent modification happened""",
            },
        ],
        references=[
            "https://cwe.mitre.org/data/definitions/362.html",
        ],
    )


@_register("graphql")
def _graphql_fix(title: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="GraphQL Security Remediation",
        description="Implement depth limiting, rate limiting, query cost analysis, and authentication.",
        severity=severity,
        code_fixes=[
            {
                "language": "python",
                "label": "GraphQL Depth & Complexity Limits",
                "code": """from graphql import validate, build_schema
from graphql.validation import ValidationRule

class DepthLimitValidator(ValidationRule):
    def __init__(self, max_depth: int = 5):
        super().__init__()
        self.max_depth = max_depth

    def enter_selection_set(self, node, key, parent, path, ancestors):
        depth = len(path) // 2
        if depth > self.max_depth:
            self.report_error(f"Query exceeds max depth of {self.max_depth}")
        return super().enter_selection_set(node, key, parent, path, ancestors)

# Use with Strawberry / Ariadne / Graphene:
# schema = build_schema(sdl)
# errors = validate(schema, document, [DepthLimitValidator(max_depth=5)])""",
            },
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
        ],
    )


@_register("csp")
def _csp_fix(title: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="CSP (Content Security Policy) Remediation",
        description="Implement a strict Content Security Policy to prevent XSS and data injection.",
        severity=severity,
        config_fixes=[
            {
                "title": "Strict CSP Header",
                "code": """# Strict CSP - blocks most injection attacks
Content-Security-Policy: "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self';" """,
            },
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
        ],
    )


@_register("firebase")
def _firebase_fix(title: str, severity: str) -> FixSuggestion:
    return FixSuggestion(
        title="Firebase Security Remediation",
        description="Restrict Firebase Realtime Database / Firestore security rules.",
        severity=severity,
        config_fixes=[
            {
                "title": "Firestore Security Rules",
                "code": """rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // UNSAFE: match /{document=**} { allow read, write: if true; }

    // SAFE - authenticated access only:
    match /users/{userId} {
      allow read, write: if request.auth != null
                        && request.auth.uid == userId;
    }

    match /posts/{post} {
      allow read: if true;
      allow create: if request.auth != null;
      allow update, delete: if request.auth != null
                          && resource.data.author == request.auth.uid;
    }
  }
}""",
            },
            {
                "title": "Realtime Database Security Rules",
                "code": """{
  "rules": {
    // UNSAFE: { ".read": true, ".write": true }

    // SAFE:
    "users": {
      "$uid": {
        ".read": "$uid === auth.uid",
        ".write": "$uid === auth.uid"
      }
    },
    "posts": {
      ".read": true,
      "$post": {
        ".write": "auth !== null",
        ".validate": "newData.hasChildren(['title', 'body'])"
      }
    }
  }
}""",
            },
        ],
        references=[
            "https://firebase.google.com/docs/rules",
        ],
    )


def _generic_fix(title: str, severity: str, category: str) -> FixSuggestion:
    return FixSuggestion(
        title=f"Remediation for {category.title() if category else 'Security Finding'}",
        description="Review this finding and apply OWASP-recommended fixes. Input validation, output encoding, and least privilege are the core principles.",
        severity=severity,
        references=[
            "https://owasp.org/www-project-top-ten/",
            "https://cwe.mitre.org/",
        ],
    )
