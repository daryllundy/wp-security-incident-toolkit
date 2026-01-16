from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography.fernet import Fernet

from .utils import ensure_directory, sha256_file


@dataclass
class QuarantineRecord:
    original_path: str
    quarantine_path: str
    sha256: str
    quarantined_at: str


class QuarantineManager:
    def __init__(self, quarantine_dir: str | Path) -> None:
        self.quarantine_dir = Path(quarantine_dir)
        ensure_directory(self.quarantine_dir)
        self.key_path = self.quarantine_dir / "quarantine.key"
        self._fernet = Fernet(self._load_or_create_key())

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            return self.key_path.read_bytes()
        key = Fernet.generate_key()
        self.key_path.write_bytes(key)
        return key

    def quarantine_file(self, file_path: str | Path) -> QuarantineRecord:
        path = Path(file_path)
        encrypted_path = self.quarantine_dir / f"{path.name}.enc"
        encrypted_data = self._fernet.encrypt(path.read_bytes())
        encrypted_path.write_bytes(encrypted_data)
        sha256 = sha256_file(path)
        path.unlink()
        record = QuarantineRecord(
            original_path=str(path),
            quarantine_path=str(encrypted_path),
            sha256=sha256,
            quarantined_at=datetime.utcnow().isoformat(),
        )
        self._write_record(record)
        return record

    def _write_record(self, record: QuarantineRecord) -> None:
        records_path = self.quarantine_dir / "records.json"
        if records_path.exists():
            payload = json.loads(records_path.read_text(encoding="utf-8"))
        else:
            payload = []
        payload.append(record.__dict__)
        records_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def restore_file(self, record: QuarantineRecord, destination: str | Path) -> None:
        encrypted_path = Path(record.quarantine_path)
        decrypted_data = self._fernet.decrypt(encrypted_path.read_bytes())
        destination_path = Path(destination)
        destination_path.write_bytes(decrypted_data)
