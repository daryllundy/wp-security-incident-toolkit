from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .reporter import SecurityReport
from .scanner_engine import WordPressSecurityScanner


@dataclass
class CustomerSite:
    id: str
    site_path: str


class PressableSecurityAPI:
    def scan_customer_sites(self, customer_list: list[CustomerSite]) -> dict:
        results = {}
        for customer in customer_list:
            scanner = WordPressSecurityScanner(customer.site_path)
            results[customer.id] = scanner.full_scan()
        return results

    def generate_hosting_report(self, results: dict) -> dict:
        return SecurityReport.generate_hosting_summary(results)
