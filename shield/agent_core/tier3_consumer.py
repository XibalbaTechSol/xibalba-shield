"""Durable, fail-closed consumer for post-containment Tier 3 responses."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

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
                 mode: Literal["shadow", "enforce"] = "shadow") -> None:
        if mode not in {"shadow", "enforce"}:
            raise ValueError("mode must be shadow or enforce")
        self.path = Path(store_path)
        self.action_broker = action_broker
        self.mode = mode
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
        if self.mode != "enforce" or response.verdict != "release" or self.action_broker is None:
            return Tier3Outcome(False, response.verdict, "shadow mode" if self.mode == "shadow" else "no releasable action", disagree)
        return Tier3Outcome(False, response.verdict, "release requires verified process identity", disagree)

    def recorded_count(self) -> int:
        with sqlite3.connect(self.path) as db:
            return int(db.execute("SELECT COUNT(*) FROM tier3_adjudications").fetchone()[0])
