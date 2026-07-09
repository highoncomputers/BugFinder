from __future__ import annotations

import json
import logging
from typing import Any, Optional

import httpx

from bugfinder.core.config import Settings

logger = logging.getLogger(__name__)


async def create_github_issue(title: str, body: str, labels: list[str] | None = None) -> bool:
    settings = Settings()
    gh_token = getattr(settings, "github_token", "")
    gh_repo = getattr(settings, "github_repo", "")

    if not gh_token or not gh_repo:
        logger.warning("GitHub issues not configured: token or repo missing")
        return False

    url = f"https://api.github.com/repos/{gh_repo}/issues"

    payload = {
        "title": f"BugFinder: {title}",
        "body": body,
        "labels": labels or ["bug", "security"],
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                url,
                json=payload,
                headers={
                    "Authorization": f"Bearer {gh_token}",
                    "Accept": "application/vnd.github.v3+json",
                },
            )
            if resp.status_code == 201:
                issue_url = resp.json().get("html_url", "")
                logger.info("GitHub issue created: %s", issue_url)
                return True
            logger.warning("GitHub issue creation failed: %d %s", resp.status_code, resp.text)
            return False
    except Exception as e:
        logger.error("GitHub issue error: %s", e)
        return False


async def create_finding_issue(finding: Any, repo: str | None = None) -> bool:
    title = getattr(finding, "title", "") or (isinstance(finding, dict) and finding.get("title", "")) or "Security Finding"
    description = getattr(finding, "description", "") or (isinstance(finding, dict) and finding.get("description", "")) or ""
    severity = ""
    if hasattr(finding, "severity"):
        severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    elif isinstance(finding, dict):
        severity = finding.get("severity", "info")

    remediation = getattr(finding, "remediation", "") or (isinstance(finding, dict) and finding.get("remediation", "")) or ""

    body = f"""## Security Finding: {title}

**Severity:** {severity}

**Description:**
{description}

**Remediation:**
{remediation}

---
*This issue was automatically created by BugFinder.*
"""

    labels = ["security", f"severity-{severity}"]

    if repo:
        # Override repo from config for this call
        old_repo = getattr(Settings(), "github_repo", "")
        Settings.github_repo = repo

    return await create_github_issue(title, body, labels)
