from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .utils import FileFinding, read_text


@dataclass
class DetectionResult:
    file_path: str
    rule: str
    severity: str
    description: str


CRYPTO_PATTERNS = {
    "coinhive": re.compile(r"coinhive|coin-hive|cryptonight", re.IGNORECASE),
    "stratum": re.compile(r"stratum\+tcp|mining_pool|miner\.js", re.IGNORECASE),
    "webassembly_miner": re.compile(r"WebAssembly\.instantiate|wasm", re.IGNORECASE),
}

BACKDOOR_PATTERNS = {
    "eval_base64": re.compile(r"eval\s*\(\s*base64_decode", re.IGNORECASE),
    "system_get": re.compile(r"system\s*\(\s*\$_(GET|POST|REQUEST)", re.IGNORECASE),
    "shell_exec": re.compile(r"shell_exec\s*\(", re.IGNORECASE),
    "preg_replace_eval": re.compile(r"preg_replace\s*\(.*/e", re.IGNORECASE),
    "assert_exec": re.compile(r"assert\s*\(\s*\$_(GET|POST|REQUEST)", re.IGNORECASE),
}


class CryptoMinerDetector:
    def scan_directory(self, directory: str | Path) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        for path in Path(directory).rglob("*"):
            if not path.is_file():
                continue
            content = read_text(path)
            for rule_name, pattern in CRYPTO_PATTERNS.items():
                if pattern.search(content):
                    findings.append(
                        DetectionResult(
                            file_path=str(path),
                            rule=rule_name,
                            severity="high",
                            description="Potential crypto mining artifact",
                        )
                    )
        return findings


class BackdoorDetector:
    def scan_directory(self, directory: str | Path) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        for path in Path(directory).rglob("*"):
            if not path.is_file():
                continue
            content = read_text(path)
            for rule_name, pattern in BACKDOOR_PATTERNS.items():
                if pattern.search(content):
                    findings.append(
                        DetectionResult(
                            file_path=str(path),
                            rule=rule_name,
                            severity="critical",
                            description="Potential backdoor indicator",
                        )
                    )
        return findings


def find_suspicious_code(content: str) -> list[tuple[int, str, str]]:
    suspicious_patterns = {
        "obfuscated_eval": re.compile(r"eval\s*\(\s*\$", re.IGNORECASE),
        "gzinflate": re.compile(r"gzinflate\s*\(", re.IGNORECASE),
        "rot13": re.compile(r"str_rot13\s*\(", re.IGNORECASE),
        "remote_include": re.compile(
            r"(include|require)\s*\(\s*['\"]https?://", re.IGNORECASE
        ),
    }
    findings: list[tuple[int, str, str]] = []
    for index, line in enumerate(content.splitlines(), start=1):
        for name, pattern in suspicious_patterns.items():
            if pattern.search(line):
                findings.append((index, line.strip()[:200], name))
    return findings


def findings_from_matches(
    file_path: str, matches: Iterable[tuple[int, str, str]]
) -> list[FileFinding]:
    results: list[FileFinding] = []
    for line_number, snippet, rule in matches:
        results.append(
            FileFinding(
                file_path=file_path,
                line_number=line_number,
                snippet=snippet,
                rule=rule,
                severity="medium",
            )
        )
    return results
