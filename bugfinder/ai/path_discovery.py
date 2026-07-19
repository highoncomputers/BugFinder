from __future__ import annotations

import json
import logging
from typing import Any

from bugfinder.ai.client import get_ai_client
from bugfinder.core.config import Settings

logger = logging.getLogger(__name__)


class AIPathDiscoverer:
    def __init__(self):
        self.settings = Settings()
        self.client = get_ai_client()

    async def discover_paths(self, base_url: str, existing_paths: list[str] | None = None) -> list[dict[str, Any]]:
        existing = existing_paths or []
        if self.client and self.settings.ai_enabled:
            prompt = f"""Given a web application at {base_url} and these discovered endpoints:
{json.dumps(existing, indent=2)}

Suggest 10-15 additional endpoints/paths that are likely to exist based on common patterns.
Return as JSON: {{"paths": [{{"path": string, "reasoning": string, "method": string, "tech_hint": string}}]}}
Focus on: admin panels, API endpoints, debug pages, configuration files, backup files.
"""
            try:
                response = await self.client.chat_json(prompt)
                if isinstance(response, dict) and "paths" in response:
                    return response["paths"]
            except Exception as e:
                logger.error("AI path discovery failed: %s", e)

        return self._common_paths(base_url)

    def _common_paths(self, base_url: str) -> list[dict[str, Any]]:
        return [
            {"path": "/admin", "reasoning": "Common admin panel", "method": "GET", "tech_hint": "generic"},
            {"path": "/api", "reasoning": "API root", "method": "GET", "tech_hint": "generic"},
            {"path": "/api/v1", "reasoning": "API v1 endpoint", "method": "GET", "tech_hint": "rest"},
            {"path": "/.env", "reasoning": "Environment config file", "method": "GET", "tech_hint": "generic"},
            {"path": "/robots.txt", "reasoning": "Robots disallow rules", "method": "GET", "tech_hint": "generic"},
            {"path": "/sitemap.xml", "reasoning": "Sitemap for crawling", "method": "GET", "tech_hint": "generic"},
            {"path": "/backup", "reasoning": "Backup directory", "method": "GET", "tech_hint": "generic"},
            {"path": "/.git/config", "reasoning": "Git repo exposure", "method": "GET", "tech_hint": "git"},
            {"path": "/swagger.json", "reasoning": "Swagger API docs", "method": "GET", "tech_hint": "swagger"},
            {"path": "/graphql", "reasoning": "GraphQL endpoint", "method": "POST", "tech_hint": "graphql"},
            {"path": "/actuator/health", "reasoning": "Spring Boot health", "method": "GET", "tech_hint": "spring"},
            {"path": "/wp-admin", "reasoning": "WordPress admin", "method": "GET", "tech_hint": "wordpress"},
            {"path": "/phpinfo.php", "reasoning": "PHP info dump", "method": "GET", "tech_hint": "php"},
            {"path": "/server-status", "reasoning": "Apache status page", "method": "GET", "tech_hint": "apache"},
            {"path": "/crossdomain.xml", "reasoning": "Flash crossdomain policy", "method": "GET", "tech_hint": "flash"},
        ]
