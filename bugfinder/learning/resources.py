from __future__ import annotations

LEARNING_RESOURCES: dict[str, list[dict[str, str]]] = {
    "xss": [
        {"title": "Cross Site Scripting (XSS)", "url": "https://owasp.org/www-community/attacks/xss/"},
        {"title": "XSS Filter Evasion", "url": "https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html"},
    ],
    "sqli": [
        {"title": "SQL Injection", "url": "https://owasp.org/www-community/attacks/SQL_Injection.html"},
        {"title": "SQL Injection Prevention", "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"},
    ],
    "ssrf": [
        {"title": "Server Side Request Forgery", "url": "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery.html"},
    ],
    "auth": [
        {"title": "Authentication Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"},
        {"title": "Authorization Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"},
    ],
    "general": [
        {"title": "OWASP Top 10", "url": "https://owasp.org/www-project-top-ten/"},
        {"title": "PortSwigger Web Security Academy", "url": "https://portswigger.net/web-security"},
        {"title": "HackerOne Hacktivity", "url": "https://hackerone.com/hacktivity"},
    ],
}


def get_resources(category: str) -> list[dict[str, str]]:
    return LEARNING_RESOURCES.get(category, LEARNING_RESOURCES["general"])


def get_all_resources() -> dict[str, list[dict[str, str]]]:
    return dict(LEARNING_RESOURCES)
