"""Durable, fail-closed consumer for post-containment Tier 3 responses."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal

from shield.schemas.events import EscalationResponse, Tier3Verdict


@dataclass(frozen=True)
class Tier3Outcome:
    applied: bool
    verdict: Tier3Verdict
    reason: str
    disagreed_with_local: bool


class Tier3Consumer:
    """Record every response before considering actuation; shadow mode never actuates."""

    def __init__(self, store_path: Path, *, action_broker=None,
                 mode: Literal["shadow", "enforce"] = "shadow",
                 max_actions_per_window: int = 10, window_seconds: float = 60.0,
                 disabled_flag_path: Path | None = None,
                 pid_identity: Callable[[int], str | None] | None = None) -> None:
        if mode not in {"shadow", "enforce"}:
            raise ValueError("mode must be shadow or enforce")
        self.path = Path(store_path)
        self.action_broker = action_broker
        self.mode = mode
        if max_actions_per_window < 1 or window_seconds <= 0:
            raise ValueError("action limits must be positive")
        self.max_actions = max_actions_per_window
        self.window_seconds = window_seconds
        self.disabled_flag_path = Path(disabled_flag_path) if disabled_flag_path else None
        self.pid_identity = pid_identity
        self._action_times: list[float] = []
        self._limit_lock = threading.Lock()
        self._tripped = False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS tier3_adjudications (id INTEGER PRIMARY KEY, response TEXT NOT NULL)")

    def apply(self, response: EscalationResponse) -> Tier3Outcome:
        payload = json.dumps({"verdict": response.verdict, "reason": response.reason,
                              "decision": response.decision.__dict__}, sort_keys=True)
        try:
            with sqlite3.connect(self.path) as db:
                db.execute("INSERT INTO tier3_adjudications(response) VALUES (?)", (payload,))
        except (OSError, sqlite3.Error) as exc:
            return Tier3Outcome(False, response.verdict, f"not recorded: {exc}", response.verdict == "release")

        disagree = response.verdict == "release" and response.decision.action == "contain"
        if self.disabled_flag_path is not None and self.disabled_flag_path.exists():
            return Tier3Outcome(False, response.verdict, "tier3_disabled", disagree)
        if self.mode != "enforce" or response.verdict != "release" or self.action_broker is None:
            return Tier3Outcome(False, response.verdict, "shadow mode" if self.mode == "shadow" else "no releasable action", disagree)
        now = time.monotonic()
        with self._limit_lock:
            self._action_times = [t for t in self._action_times if now - t < self.window_seconds]
            if self._tripped or len(self._action_times) >= self.max_actions:
                self._tripped = True
                return Tier3Outcome(False, response.verdict, "tier3_action_cap", disagree)
            self._action_times.append(now)
        pid = getattr(response, "pid", None)
        expected = getattr(response, "pid_identity", None)
        if not isinstance(pid, int) or not isinstance(expected, str):
            return Tier3Outcome(False, response.verdict, "release requires verified process identity", disagree)
        if self.pid_identity is None:
            return Tier3Outcome(False, response.verdict, "release requires verified process identity", disagree)
        current = self.pid_identity(pid)
        if current is None:
            return Tier3Outcome(False, response.verdict, "pid_gone", disagree)
        if current != expected:
            return Tier3Outcome(False, response.verdict, "pid_identity_mismatch", disagree)
        try:
            self.action_broker.resume(pid)
        except Exception as exc:  # noqa: BLE001 -- leave process contained
            return Tier3Outcome(False, response.verdict, f"resume_failed: {exc}", disagree)
        return Tier3Outcome(True, response.verdict, "resumed", disagree)

    @property
    def tripped(self) -> bool:
        return self._tripped

    def recorded_count(self) -> int:
        with sqlite3.connect(self.path) as db:
            return int(db.execute("SELECT COUNT(*) FROM tier3_adjudications").fetchone()[0])
