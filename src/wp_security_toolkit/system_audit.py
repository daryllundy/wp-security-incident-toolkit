from __future__ import annotations

import os
from pathlib import Path


class SystemAuditor:
    def __init__(self, root_path: str | Path = "/") -> None:
        self.root_path = Path(root_path)

    def audit(self) -> dict:
        world_writable = []
        suid_files = []
        for path in self.root_path.rglob("*"):
            if not path.is_file():
                continue
            try:
                mode = path.stat().st_mode
            except OSError:
                continue
            if mode & 0o002:
                world_writable.append(str(path))
            if mode & 0o4000:
                suid_files.append(str(path))
        return {
            "world_writable_files": world_writable[:50],
            "suid_files": suid_files[:50],
            "recommendations": [
                "Review world-writable files for necessity.",
                "Ensure SUID binaries are required and patched.",
                "Run rootkit scanners like rkhunter or chkrootkit.",
            ],
        }

    def apply_recommendations(self) -> dict:
        return {
            "status": "manual",
            "message": "Review recommendations and apply changes manually.",
        }
