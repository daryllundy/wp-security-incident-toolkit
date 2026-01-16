from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests

from .utils import load_json, save_json


DEFAULT_FEED = {
    "ips": {"192.0.2.1", "203.0.113.5"},
    "domains": {"malicious-example.com", "bad-domain.test"},
    "hashes": {"e3b0c44298fc1c149afbf4c8996fb924"},
}


@dataclass
class ThreatResult:
    indicator: str
    malicious: bool
    confidence: str
    source: str


class ThreatIntelligence:
    def __init__(self, feed_path: Optional[str | Path] = None) -> None:
        self.feed_path = Path(feed_path) if feed_path else None
        self.feed = self._load_feed()

    def _load_feed(self) -> dict:
        if self.feed_path and self.feed_path.exists():
            data = load_json(self.feed_path)
            if data:
                return {
                    "ips": set(data.get("ips", [])),
                    "domains": set(data.get("domains", [])),
                    "hashes": set(data.get("hashes", [])),
                }
        return {
            "ips": set(DEFAULT_FEED["ips"]),
            "domains": set(DEFAULT_FEED["domains"]),
            "hashes": set(DEFAULT_FEED["hashes"]),
        }

    def update_from_url(self, feed_url: str) -> dict:
        response = requests.get(feed_url, timeout=10)
        response.raise_for_status()
        data = response.json()
        self.feed = {
            "ips": set(data.get("ips", [])),
            "domains": set(data.get("domains", [])),
            "hashes": set(data.get("hashes", [])),
        }
        if self.feed_path:
            save_json(
                self.feed_path,
                {
                    "ips": list(self.feed["ips"]),
                    "domains": list(self.feed["domains"]),
                    "hashes": list(self.feed["hashes"]),
                },
            )
        return data

    def check_ip(self, ip_address: str) -> ThreatResult:
        malicious = ip_address in self.feed["ips"]
        return ThreatResult(
            ip_address, malicious, self._confidence(malicious), "threat_feed"
        )

    def check_domain(self, domain: str) -> ThreatResult:
        malicious = domain in self.feed["domains"]
        return ThreatResult(
            domain, malicious, self._confidence(malicious), "threat_feed"
        )

    def check_file_hash(self, file_hash: str) -> ThreatResult:
        malicious = file_hash in self.feed["hashes"]
        return ThreatResult(
            file_hash, malicious, self._confidence(malicious), "threat_feed"
        )

    @staticmethod
    def _confidence(malicious: bool) -> str:
        return "high" if malicious else "low"
