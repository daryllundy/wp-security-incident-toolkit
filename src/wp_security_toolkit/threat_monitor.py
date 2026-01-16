from __future__ import annotations

import time
from pathlib import Path

from .scanner_engine import WordPressSecurityScanner
from .threat_intelligence import ThreatIntelligence


class ThreatMonitor:
    def __init__(
        self, root_path: str | Path, feed_path: str | Path | None = None
    ) -> None:
        self.root_path = Path(root_path)
        self.threat_intel = ThreatIntelligence(feed_path)

    def run_once(self) -> dict:
        scanner = WordPressSecurityScanner(self.root_path)
        scan_results = scanner.full_scan()
        return {
            "scan": scan_results,
            "threat_feed": {
                "ips": len(self.threat_intel.feed["ips"]),
                "domains": len(self.threat_intel.feed["domains"]),
                "hashes": len(self.threat_intel.feed["hashes"]),
            },
        }

    def run_daemon(self, interval: int = 300) -> None:
        while True:
            self.run_once()
            time.sleep(interval)
