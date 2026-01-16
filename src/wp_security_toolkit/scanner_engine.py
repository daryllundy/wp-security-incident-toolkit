from __future__ import annotations

import concurrent.futures
import re
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

try:
    import yara
except ImportError:  # pragma: no cover - optional dependency
    yara = None

from .detectors import (
    BackdoorDetector,
    CryptoMinerDetector,
    find_suspicious_code,
    findings_from_matches,
)
from .utils import FileFinding, iter_files, normalize_rule_matches, read_text


FALLBACK_YARA_PATTERNS = {
    "wordpress_backdoor": re.compile(
        r"eval\s*\(\s*base64_decode|system\s*\(\s*\$_", re.IGNORECASE
    ),
    "suspicious_wp_config": re.compile(r"wp-config\.php", re.IGNORECASE),
}

BEHAVIORAL_PATTERN = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")


class YaraScanner:
    def __init__(self, rules_path: str | Path | None = None) -> None:
        self.rules_path = Path(rules_path) if rules_path else None
        self._rules = None
        if yara and self.rules_path and self.rules_path.exists():
            self._rules = yara.compile(filepath=str(self.rules_path))

    def scan(self, file_path: Path, content: str) -> list[str]:
        if self._rules:
            matches = self._rules.match(data=content)
            return [match.rule for match in matches]
        matches = []
        for name, pattern in FALLBACK_YARA_PATTERNS.items():
            if pattern.search(content):
                matches.append(name)
        return matches


class WordPressSecurityScanner:
    def __init__(
        self, root_path: str | Path, rules_path: str | Path | None = None
    ) -> None:
        self.root_path = Path(root_path)
        default_rules = Path(__file__).resolve().parents[2] / "rules" / "default.yar"
        self.yara_scanner = YaraScanner(rules_path or default_rules)
        self.crypto_detector = CryptoMinerDetector()
        self.backdoor_detector = BackdoorDetector()

    def full_scan(self) -> dict:
        files = list(iter_files(self.root_path))
        findings = self._scan_files(files)
        crypto_hits = self.crypto_detector.scan_directory(self.root_path)
        backdoor_hits = self.backdoor_detector.scan_directory(self.root_path)
        vulnerabilities = self.check_vulnerabilities()
        return self._build_result(findings, crypto_hits, backdoor_hits, vulnerabilities)

    def quick_scan(self) -> dict:
        critical_files = self._critical_files()
        findings = self._scan_files(critical_files)
        return self._build_result(findings, [], [], self.check_vulnerabilities())

    def scan_with_rules(self, rules_path: str | Path) -> dict:
        self.yara_scanner = YaraScanner(rules_path)
        return self.full_scan()

    def scan_wordpress_installation(self) -> dict:
        return self.full_scan()

    def check_vulnerabilities(self) -> list[dict]:
        vulnerabilities = []
        wp_version_file = self.root_path / "wp-includes" / "version.php"
        if wp_version_file.exists():
            content = read_text(wp_version_file)
            match = re.search(r"\$wp_version\s*=\s*'([^']+)'", content)
            if match:
                vulnerabilities.append(
                    {
                        "type": "core_version",
                        "version": match.group(1),
                        "severity": "medium",
                        "description": "Verify WordPress core version against latest release.",
                    }
                )
        readme = self.root_path / "readme.html"
        if readme.exists():
            vulnerabilities.append(
                {
                    "type": "public_readme",
                    "severity": "low",
                    "description": "Remove public readme.html to reduce info disclosure.",
                }
            )
        xmlrpc = self.root_path / "xmlrpc.php"
        if xmlrpc.exists():
            vulnerabilities.append(
                {
                    "type": "xmlrpc_enabled",
                    "severity": "medium",
                    "description": "Restrict xmlrpc.php access if unused.",
                }
            )
        plugins_dir = self.root_path / "wp-content" / "plugins"
        if plugins_dir.exists():
            for plugin in plugins_dir.iterdir():
                if plugin.is_dir():
                    vulnerabilities.append(
                        {
                            "type": "plugin_review",
                            "severity": "low",
                            "description": f"Review plugin {plugin.name} for known vulnerabilities.",
                        }
                    )
        return vulnerabilities

    def _critical_files(self) -> list[Path]:
        candidates = [
            self.root_path / "wp-config.php",
            self.root_path / ".htaccess",
            self.root_path / "index.php",
        ]
        return [path for path in candidates if path.exists()]

    def _scan_files(self, files: Iterable[Path]) -> list[FileFinding]:
        findings: list[FileFinding] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            for file_findings in executor.map(self._scan_file, files):
                findings.extend(file_findings)
        return findings

    def _scan_file(self, path: Path) -> list[FileFinding]:
        content = read_text(path)
        yara_matches = normalize_rule_matches(self.yara_scanner.scan(path, content))
        suspicious_matches = find_suspicious_code(content)
        findings = findings_from_matches(str(path), suspicious_matches)
        if BEHAVIORAL_PATTERN.search(content):
            findings.append(
                FileFinding(
                    file_path=str(path),
                    line_number=None,
                    snippet="Behavioral anomaly: large encoded payload",
                    rule="behavioral_anomaly",
                    severity="high",
                )
            )
        for match in yara_matches:
            findings.append(
                FileFinding(
                    file_path=str(path),
                    line_number=None,
                    snippet=f"Matched YARA rule: {match}",
                    rule=match,
                    severity="high",
                )
            )
        return findings

    def _build_result(
        self,
        findings: list[FileFinding],
        crypto_hits: list,
        backdoor_hits: list,
        vulnerabilities: list[dict],
    ) -> dict:
        summary = {
            "files_scanned": len(list(iter_files(self.root_path))),
            "total_findings": len(findings),
            "crypto_hits": len(crypto_hits),
            "backdoor_hits": len(backdoor_hits),
        }
        security_score = self._security_score(findings, vulnerabilities)
        return {
            "root_path": str(self.root_path),
            "findings": [asdict(finding) for finding in findings],
            "crypto_hits": [hit.__dict__ for hit in crypto_hits],
            "backdoor_hits": [hit.__dict__ for hit in backdoor_hits],
            "vulnerabilities": vulnerabilities,
            "summary": summary,
            "security_score": security_score,
        }

    @staticmethod
    def _security_score(
        findings: list[FileFinding], vulnerabilities: list[dict]
    ) -> dict:
        score = 100
        severity_weights = {"critical": 20, "high": 12, "medium": 6, "low": 3}
        for finding in findings:
            score -= severity_weights.get(finding.severity, 2)
        for vulnerability in vulnerabilities:
            score -= severity_weights.get(vulnerability.get("severity", "low"), 3)
        score = max(score, 0)
        return {
            "score": score,
            "risk_level": "high" if score < 50 else "medium" if score < 80 else "low",
        }
