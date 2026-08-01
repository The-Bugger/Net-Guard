"""
export_service.py — ExportService: serialise detection events to JSON/CSV/Markdown/PDF.

Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone


class ExportService:
    def __init__(self, event_repo) -> None:
        """Initialize ExportService with an EventRepository instance."""
        self._repo = event_repo

    # ------------------------------------------------------------------
    # Public format methods
    # ------------------------------------------------------------------

    def export_json(self, filters: dict) -> tuple[bytes, str]:
        """Returns (json_bytes, filename). Req 6.1."""
        events = self._fetch_events(filters)
        return json.dumps(events, indent=2).encode(), self._filename("json")

    def export_csv(self, filters: dict) -> tuple[str, str]:
        """Returns (csv_string, filename). Req 6.2."""
        events = self._fetch_events(filters)
        if not events:
            return "", self._filename("csv")
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=list(events[0].keys()))
        writer.writeheader()
        writer.writerows(events)
        return buf.getvalue(), self._filename("csv")

    def export_markdown(self, filters: dict) -> tuple[str, str]:
        """Returns (markdown_string, filename). Req 6.3."""
        events = self._fetch_events(filters)
        lines = [
            "# NetGuard Detection Export",
            f"\nGenerated: {datetime.now(timezone.utc).isoformat()}",
            f"\nTotal events: {len(events)}",
            "\n## Summary\n",
            "| # | Timestamp | Attack Type | Severity | Source IP |",
            "|---|-----------|-------------|----------|-----------|",
        ]
        for i, e in enumerate(events, 1):
            lines.append(
                f"| {i} | {e.get('timestamp','')} | {e.get('attack_type','')} "
                f"| {e.get('severity','')} | {e.get('source_ip','')} |"
            )
        lines.append("\n## Events\n")
        for e in events:
            lines.append(
                f"### {e.get('attack_type','Unknown')} — {e.get('timestamp','')}\n"
                f"- **Severity:** {e.get('severity','')}\n"
                f"- **Source IP:** {e.get('source_ip','')}\n"
                f"- **Rule:** {e.get('rule_name','')}\n"
                f"- **Explanation:** {e.get('explanation','')}\n"
                f"- **Recommendation:** {e.get('recommendation','')}\n"
            )
        return "\n".join(lines), self._filename("md")

    def export_pdf(self, filters: dict) -> tuple[bytes, str]:
        """Returns (pdf_bytes, filename). Raises ImportError if reportlab/weasyprint absent. Req 6.4."""
        # Try reportlab first, then weasyprint — both optional
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas as rl_canvas
        except ImportError:
            try:
                import weasyprint as _wp  # noqa: F401
            except ImportError:
                raise ImportError("Neither reportlab nor weasyprint is installed.")
            # weasyprint path
            md_content, _ = self.export_markdown(filters)
            html = f"<html><body><pre>{md_content}</pre></body></html>"
            import weasyprint
            pdf_bytes = weasyprint.HTML(string=html).write_pdf()
            return pdf_bytes, self._filename("pdf")

        # reportlab path
        events = self._fetch_events(filters)
        buf = io.BytesIO()
        c = rl_canvas.Canvas(buf, pagesize=letter)
        c.setFont("Helvetica", 10)
        y = 750
        c.drawString(50, y, f"NetGuard Export — {datetime.now(timezone.utc).date()}")
        y -= 20
        for e in events:
            line = f"{e.get('timestamp','')}  {e.get('attack_type','')}  {e.get('severity','')}  {e.get('source_ip','')}"
            c.drawString(50, y, line[:100])
            y -= 14
            if y < 50:
                c.showPage()
                y = 750
        c.save()
        return buf.getvalue(), self._filename("pdf")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _fetch_events(self, filters: dict) -> list[dict]:
        """Return up to 10 000 events from the repository matching the given filters."""
        return self._repo.get_all(filters=filters, limit=10000, offset=0)

    def _filename(self, fmt: str) -> str:
        """Return a datestamped export filename for the given format extension."""
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return f"netguard-export-{date_str}.{fmt}"
