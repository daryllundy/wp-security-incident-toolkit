from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence


TEXT_EXTENSIONS = {".php", ".js", ".html", ".htm", ".phtml", ".txt", ".json"}


@dataclass
class FileFinding:
    file_path: str
    line_number: int | None
    snippet: str
    rule: str
    severity: str


def iter_files(
    root: str | Path, extensions: Sequence[str] | None = None
) -> Iterator[Path]:
    root_path = Path(root)
    if not root_path.exists():
        return iter(())
    if extensions is None:
        extensions = list(TEXT_EXTENSIONS)
    for path in root_path.rglob("*"):
        if path.is_file() and (not extensions or path.suffix.lower() in extensions):
            yield path


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def get_modification_time(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def normalize_rule_matches(matches: Iterable[str]) -> list[str]:
    return sorted({match for match in matches if match})
