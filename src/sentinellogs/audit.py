from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from threading import Lock
from typing import Any


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._previous_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        last = "0" * 64
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict) and isinstance(value.get("hash"), str):
                    last = value["hash"]
        return last

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            entry = {"previous_hash": self._previous_hash, "event": event}
            digest = hashlib.sha256(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
            entry["hash"] = digest
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n")
            self._previous_hash = digest
            return entry

    def verify(self) -> bool:
        previous = "0" * 64
        if not self.path.exists():
            return True
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    entry = json.loads(line)
                    supplied = entry.pop("hash")
                except (json.JSONDecodeError, KeyError, TypeError):
                    return False
                if entry.get("previous_hash") != previous:
                    return False
                expected = hashlib.sha256(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
                if not isinstance(supplied, str) or not hmac.compare_digest(supplied, expected):
                    return False
                previous = supplied
        return True