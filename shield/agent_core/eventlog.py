"""
Local JSONL decision log — backs `shield status` / `shield events --recent` (spec §4.6).

Deliberately local and file-based, not a database: §4.6 states the diagnostics goal plainly
("a security product an admin cannot explain in one command is a security product they will
disable during an incident") — a plain file an admin can `tail` or `grep` without any other
tooling is the simplest thing that satisfies that.
"""

from __future__ import annotations

import json
import threading
import hashlib
import hmac
from pathlib import Path

from ..schemas.events import PolicyDecision


class EventLog:
    def __init__(self, path: Path, *, integrity_key_path: Path | None = None):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.integrity_key_path = integrity_key_path
        self._lock = threading.Lock()

    def append(self, decision: PolicyDecision) -> None:
        with self._lock:
            row = decision.to_dict()
            if self.integrity_key_path is not None:
                row["_integrity"] = self._integrity_for(row)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row, sort_keys=True) + "\n")

    def recent(self, n: int = 20) -> list[dict]:
        if not self.path.exists():
            return []
        with self._lock:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        out = []
        for line in lines[-n:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def count(self) -> int:
        if not self.path.exists():
            return 0
        with self._lock:
            return sum(1 for _ in self.path.open("r", encoding="utf-8"))

    def verify(self) -> dict:
        if self.integrity_key_path is None:
            return {"ok": False, "checked": 0, "reason": "integrity_key_path is required"}
        if not self.path.exists():
            return {"ok": True, "checked": 0, "reason": "log file does not exist"}
        key = self._key()
        previous_hash = ""
        checked = 0
        with self._lock:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        for line_no, line in enumerate(lines, start=1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                return {"ok": False, "checked": checked, "line": line_no, "reason": f"invalid JSON: {exc}"}
            integrity = row.pop("_integrity", None)
            if not isinstance(integrity, dict):
                return {"ok": False, "checked": checked, "line": line_no, "reason": "missing _integrity"}
            if integrity.get("previous_hash") != previous_hash:
                return {"ok": False, "checked": checked, "line": line_no, "reason": "previous hash mismatch"}
            canonical = json.dumps(row, sort_keys=True, separators=(",", ":")).encode("utf-8")
            expected_hash = hashlib.sha256(previous_hash.encode("utf-8") + canonical).hexdigest()
            if integrity.get("entry_hash") != expected_hash:
                return {"ok": False, "checked": checked, "line": line_no, "reason": "entry hash mismatch"}
            expected_hmac = hmac.new(key, expected_hash.encode("utf-8"), hashlib.sha256).hexdigest()
            if integrity.get("hmac_sha256") != expected_hmac:
                return {"ok": False, "checked": checked, "line": line_no, "reason": "HMAC mismatch"}
            previous_hash = expected_hash
            checked += 1
        return {"ok": True, "checked": checked, "last_hash": previous_hash}

    def _integrity_for(self, row: dict) -> dict:
        previous_hash = self._last_entry_hash()
        canonical = json.dumps(row, sort_keys=True, separators=(",", ":")).encode("utf-8")
        entry_hash = hashlib.sha256(previous_hash.encode("utf-8") + canonical).hexdigest()
        return {
            "algorithm": "sha256-chain+hmac-sha256",
            "previous_hash": previous_hash,
            "entry_hash": entry_hash,
            "hmac_sha256": hmac.new(self._key(), entry_hash.encode("utf-8"), hashlib.sha256).hexdigest(),
        }

    def _last_entry_hash(self) -> str:
        if not self.path.exists():
            return ""
        for line in reversed(self.path.read_text(encoding="utf-8").splitlines()):
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                return ""
            integrity = row.get("_integrity")
            if isinstance(integrity, dict) and isinstance(integrity.get("entry_hash"), str):
                return integrity["entry_hash"]
        return ""

    def _key(self) -> bytes:
        assert self.integrity_key_path is not None
        return self.integrity_key_path.read_bytes()
