from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from bugfinder.core.config import Settings
from bugfinder.reporting.html import generate_html_report

logger = logging.getLogger(__name__)


async def generate_pdf_report(target: str, scan_id: int, findings: list[Any],
                                assets: list[Any] | None = None,
                                output_path: str | None = None) -> Optional[str]:
    try:
        from weasyprint import HTML
    except ImportError:
        logger.error("weasyprint not installed. Install with: pip install bugfinder[pdf]")
        return None

    html = generate_html_report(
        target=target,
        scan_id=scan_id,
        findings=findings,
        assets=assets,
    )

    if output_path is None:
        settings = Settings()
        reports_dir = Path(settings.reports_dir)
        reports_dir.mkdir(parents=True, exist_ok=True)
        output_path = str(reports_dir / f"report_{scan_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf")

    try:
        HTML(string=html).write_pdf(output_path)
        logger.info("PDF report generated: %s", output_path)
        return output_path
    except Exception as e:
        logger.error("PDF generation failed: %s", e)
        return None
