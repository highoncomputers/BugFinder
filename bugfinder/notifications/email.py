from __future__ import annotations

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Optional

from bugfinder.core.config import Settings

logger = logging.getLogger(__name__)


async def send_email_notification(subject: str, body: str, to_email: str | None = None,
                                    html: bool = False) -> bool:
    settings = Settings()
    smtp_host = getattr(settings, "smtp_host", "")
    smtp_port = getattr(settings, "smtp_port", 587)
    smtp_user = getattr(settings, "smtp_user", "")
    smtp_password = getattr(settings, "smtp_password", "")
    email_from = getattr(settings, "email_from", "bugfinder@localhost")
    email_to = to_email or getattr(settings, "email_to", "")

    if not smtp_host or not email_to:
        logger.warning("Email not configured: SMTP host or recipient missing")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"BugFinder - {subject}"
    msg["From"] = email_from
    msg["To"] = email_to

    if html:
        msg.attach(MIMEText(body, "html"))
    else:
        msg.attach(MIMEText(body, "plain"))

    try:
        import asyncio
        loop = asyncio.get_event_loop()

        def _send():
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                if smtp_user and smtp_password:
                    server.login(smtp_user, smtp_password)
                server.sendmail(email_from, email_to, msg.as_string())

        await loop.run_in_executor(None, _send)
        logger.info("Email sent to %s: %s", email_to, subject)
        return True
    except Exception as e:
        logger.error("Email send failed: %s", e)
        return False


async def send_finding_alert(finding: Any) -> bool:
    title = getattr(finding, "title", "") or (isinstance(finding, dict) and finding.get("title", "")) or "Finding Alert"
    description = getattr(finding, "description", "") or (isinstance(finding, dict) and finding.get("description", "")) or ""
    severity = ""
    if hasattr(finding, "severity"):
        severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    elif isinstance(finding, dict):
        severity = finding.get("severity", "info")

    subject = f"[{severity.upper()}] {title}"
    body = f"""BugFinder Security Alert

Severity: {severity}
Title: {title}
Description: {description}

---
This is an automated notification from BugFinder.
"""

    return await send_email_notification(subject, body)
