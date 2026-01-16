from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .utils import load_json, save_json, sha256_file


@dataclass
class IntegrityResult:
    added: list[str]
    removed: list[str]
    modified: list[str]


class IntegrityChecker:
    def __init__(self, baseline_path: str | Path) -> None:
        self.baseline_path = Path(baseline_path)

    def create_baseline(self, root_path: str | Path, files: Iterable[Path]) -> dict:
        baseline = {str(path): sha256_file(path) for path in files}
        save_json(self.baseline_path, baseline)
        return baseline

    def compare(self, root_path: str | Path, files: Iterable[Path]) -> IntegrityResult:
        current = {str(path): sha256_file(path) for path in files}
        baseline = load_json(self.baseline_path)
        added = [path for path in current if path not in baseline]
        removed = [path for path in baseline if path not in current]
        modified = [
            path for path, digest in current.items() if baseline.get(path) != digest
        ]
        return IntegrityResult(added=added, removed=removed, modified=modified)
