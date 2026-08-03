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
from pathlib import Path

from ..schemas.events import PolicyDecision


class EventLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, decision: PolicyDecision) -> None:
        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(decision.to_dict()) + "\n")

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
