from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from .detectors import find_suspicious_code, findings_from_matches
from .incident_response import IncidentResponder
from .scanner_engine import YaraScanner
from .utils import read_text, sha256_file


class Investigator:
    def analyze_file(self, file_path: str | Path) -> dict:
        path = Path(file_path)
        content = read_text(path)
        yara_scanner = YaraScanner()
        yara_matches = yara_scanner.scan(path, content)
        suspicious = find_suspicious_code(content)
        return {
            "file_path": str(path),
            "sha256": sha256_file(path),
            "yara_matches": yara_matches,
            "suspicious_findings": [
                asdict(finding)
                for finding in findings_from_matches(str(path), suspicious)
            ],
        }

    def timeline(
        self, incident_dir: str | Path, start_date: str, end_date: str
    ) -> list[dict]:
        responder = IncidentResponder(".", incident_dir=incident_dir)
        events = responder.timeline(start_date, end_date)
        return [event.__dict__ for event in events]
