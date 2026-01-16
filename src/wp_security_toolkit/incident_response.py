from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .quarantine import QuarantineManager
from .reporter import SecurityReport
from .scanner_engine import WordPressSecurityScanner
from .utils import ensure_directory


@dataclass
class IncidentEvent:
    timestamp: str
    event_type: str
    details: dict


class IncidentResponder:
    def __init__(
        self, root_path: str | Path, incident_dir: str | Path = ".incidents"
    ) -> None:
        self.root_path = Path(root_path)
        self.incident_dir = Path(incident_dir)
        ensure_directory(self.incident_dir)
        self.events_path = self.incident_dir / "events.jsonl"
        self.quarantine = QuarantineManager(self.incident_dir / "quarantine")

    def create_report(self, site: str) -> dict:
        scanner = WordPressSecurityScanner(self.root_path)
        scan_results = scanner.full_scan()
        report = SecurityReport(scan_results)
        report_path = self.incident_dir / f"incident_report_{site}.json"
        report.generate_json(report_path)
        notification = self.notify_security_team(site, report_path)
        forensic_summary = self._forensic_summary(scan_results)
        self._log_event("report_created", {"site": site, "report": str(report_path)})
        return {
            "report": str(report_path),
            "summary": scan_results.get("summary", {}),
            "forensic_summary": forensic_summary,
            "notification": notification,
        }

    @staticmethod
    def _forensic_summary(scan_results: dict) -> dict:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in scan_results.get("findings", []):
            severity = finding.get("severity", "low")
            if severity in severity_counts:
                severity_counts[severity] += 1
        return {"severity_counts": severity_counts}

    def notify_security_team(self, site: str, report_path: Path) -> dict:
        notification = {
            "site": site,
            "report": str(report_path),
            "status": "queued",
        }
        self._log_event("notification_sent", notification)
        return notification

    def quarantine_files(self, malware_list_path: str | Path) -> list[dict]:
        malware_list = Path(malware_list_path).read_text(encoding="utf-8").splitlines()
        records = []
        for file_path in malware_list:
            if not file_path:
                continue
            record = self.quarantine.quarantine_file(file_path)
            records.append(record.__dict__)
            self._log_event("file_quarantined", record.__dict__)
        return records

    def recovery_plan(self, incident_id: str) -> dict:
        plan = {
            "incident_id": incident_id,
            "steps": [
                "Isolate affected site and restrict access.",
                "Restore known-good backups.",
                "Patch WordPress core, themes, and plugins.",
                "Rotate credentials and API keys.",
                "Re-run full security scan and monitor logs.",
            ],
        }
        self._log_event("recovery_plan_generated", plan)
        return plan

    def timeline(self, start_date: str, end_date: str) -> list[IncidentEvent]:
        events = []
        start = datetime.fromisoformat(start_date) if start_date else None
        end = datetime.fromisoformat(end_date) if end_date else None
        if self.events_path.exists():
            for line in self.events_path.read_text(encoding="utf-8").splitlines():
                if not line:
                    continue
                payload = json.loads(line)
                event = IncidentEvent(**payload)
                event_time = datetime.fromisoformat(event.timestamp)
                if start and event_time < start:
                    continue
                if end and event_time > end:
                    continue
                events.append(event)
        return events

    def _log_event(self, event_type: str, details: dict) -> None:
        event = IncidentEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type=event_type,
            details=details,
        )
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.__dict__) + "\n")
