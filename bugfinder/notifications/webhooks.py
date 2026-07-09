from __future__ import annotations

import json
import logging
from typing import Any, Optional

import httpx

from bugfinder.core.config import Settings

logger = logging.getLogger(__name__)


async def send_discord_webhook(webhook_url: str, title: str, description: str,
                                severity: str = "info", fields: list[dict] | None = None,
                                color: int | None = None) -> bool:
    colors = {"critical": 0xDC143C, "high": 0xFF4500, "medium": 0xFFA500,
              "low": 0x1E90FF, "info": 0x808080}
    embed_color = color or colors.get(severity.lower(), 0x808080)

    embed = {
        "title": title,
        "description": description[:2000],
        "color": embed_color,
        "fields": fields or [],
        "footer": {"text": "BugFinder Security Assessment"},
    }

    payload = {"embeds": [embed]}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(webhook_url, json=payload)
            if resp.status_code == 204:
                logger.info("Discord notification sent: %s", title)
                return True
            logger.warning("Discord webhook failed: %d %s", resp.status_code, resp.text)
            return False
    except Exception as e:
        logger.error("Discord webhook error: %s", e)
        return False


async def send_slack_webhook(webhook_url: str, title: str, description: str,
                              severity: str = "info") -> bool:
    emoji = {"critical": ":red_circle:", "high": ":orange_circle:", "medium": ":warning:",
             "low": ":large_blue_circle:", "info": ":information_source:"}
    sev_emoji = emoji.get(severity.lower(), ":information_source:")

    payload = {
        "text": f"{sev_emoji} *BugFinder - {title}*",
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"{sev_emoji} *{title}*"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": description[:2000]}},
            {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Severity: *{severity}*"}]},
        ],
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(webhook_url, json=payload)
            if resp.status_code == 200:
                logger.info("Slack notification sent: %s", title)
                return True
            logger.warning("Slack webhook failed: %d %s", resp.status_code, resp.text)
            return False
    except Exception as e:
        logger.error("Slack webhook error: %s", e)
        return False


async def send_teams_webhook(webhook_url: str, title: str, description: str,
                              severity: str = "info") -> bool:
    color_map = {"critical": "DC143C", "high": "FF4500", "medium": "FFA500",
                 "low": "1E90FF", "info": "808080"}

    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color_map.get(severity.lower(), "808080"),
        "title": f"BugFinder - {title}",
        "text": description[:2000],
        "sections": [{"facts": [{"name": "Severity", "value": severity}]}],
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(webhook_url, json=payload)
            if resp.status_code == 200:
                logger.info("Teams notification sent: %s", title)
                return True
            logger.warning("Teams webhook failed: %d %s", resp.status_code, resp.text)
            return False
    except Exception as e:
        logger.error("Teams webhook error: %s", e)
        return False


async def notify_finding(finding: Any, webhook_url: str | None = None,
                          service: str = "discord") -> bool:
    settings = Settings()
    url = webhook_url or ""

    if not url:
        if service == "discord":
            url = getattr(settings, "discord_webhook_url", "")
        elif service == "slack":
            url = getattr(settings, "slack_webhook_url", "")

    if not url:
        return False

    title = getattr(finding, "title", "") or "BugFinder Finding"
    description = getattr(finding, "description", "") or "No description"
    severity = ""
    if hasattr(finding, "severity"):
        severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    elif isinstance(finding, dict):
        severity = finding.get("severity", "info")

    if service == "discord":
        return await send_discord_webhook(url, title, description, severity)
    elif service == "slack":
        return await send_slack_webhook(url, title, description, severity)
    elif service == "teams":
        return await send_teams_webhook(url, title, description, severity)
    return False
