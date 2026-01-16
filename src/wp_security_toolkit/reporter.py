from __future__ import annotations

import json
from pathlib import Path
from typing import Any

report_canvas = None
report_letter = None

try:
    from reportlab.lib.pagesizes import letter as _letter
    from reportlab.pdfgen import canvas as _canvas
except ImportError:  # pragma: no cover - optional dependency
    pass
else:
    report_canvas = _canvas
    report_letter = _letter


REPORT_TYPES = {
    "executive": "High-level security overview",
    "technical": "Detailed findings and remediation guidance",
    "compliance": "Regulatory compliance status",
    "incident": "Forensic incident report",
    "trend": "Security posture trend analysis",
}


class SecurityReport:
    def __init__(self, scan_results: dict, report_type: str = "technical") -> None:
        self.scan_results = scan_results
        self.report_type = report_type if report_type in REPORT_TYPES else "technical"

    def generate_pdf(self, output_path: str | Path) -> None:
        if report_canvas is None or report_letter is None:
            raise RuntimeError("reportlab is required for PDF reports")
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        pdf = report_canvas.Canvas(str(path), pagesize=report_letter)
        pdf.setTitle("Security Report")
        pdf.drawString(40, 750, "WordPress Security Incident Report")
        pdf.drawString(40, 735, f"Report type: {self.report_type}")
        summary = self.scan_results.get("summary", {})
        pdf.drawString(40, 730, f"Files scanned: {summary.get('files_scanned', 0)}")
        pdf.drawString(40, 715, f"Total findings: {summary.get('total_findings', 0)}")
        pdf.drawString(40, 700, f"Crypto hits: {summary.get('crypto_hits', 0)}")
        pdf.drawString(40, 685, f"Backdoor hits: {summary.get('backdoor_hits', 0)}")
        pdf.showPage()
        pdf.save()

    def generate_json(self, output_path: str | Path) -> None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "report_type": self.report_type,
            "description": REPORT_TYPES[self.report_type],
            "results": self.scan_results,
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def generate_html(self, output_path: str | Path) -> None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        summary = self.scan_results.get("summary", {})
        html = f"""
        <html>
        <head><title>Security Report</title></head>
        <body>
            <h1>WordPress Security Report</h1>
            <p>Report type: {self.report_type} - {REPORT_TYPES[self.report_type]}</p>
            <p>Files scanned: {summary.get("files_scanned", 0)}</p>
            <p>Total findings: {summary.get("total_findings", 0)}</p>
            <p>Crypto hits: {summary.get("crypto_hits", 0)}</p>
            <p>Backdoor hits: {summary.get("backdoor_hits", 0)}</p>
        </body>
        </html>
        """

        path.write_text(html.strip(), encoding="utf-8")

    @staticmethod
    def generate_hosting_summary(results: dict[str, dict]) -> dict[str, Any]:
        summary = {"sites": {}, "total_sites": len(results)}
        for site, site_results in results.items():
            summary["sites"][site] = site_results.get("summary", {})
        return summary
