"""Local, append-only log of enforcement outcomes on the device.

Why this exists: the decision log (`EventLog`) records what Shield DECIDED. It does not record
what happened when the decision was carried out, nor which pid was frozen. Outcomes used to
reach only the backend, so a device-side tool (the desktop app, an operator at a terminal) could
not answer "what is frozen right now, and how do I undo it?" without a network round trip.

Format: one JSON object per line, exactly `EnforcementOutcome.to_dict()` (including `pid`).
The file is created 0600 in a 0700 directory: outcomes name processes on the device.

Fail posture: BEST-EFFORT. A write failure is logged and swallowed. Recording evidence must
never delay or prevent containment, the same stance as the backend evidence publisher. The cost
is that a failed write leaves a frozen process missing from this log; the log is a convenience
view for the operator, not the enforcement record.

Bounded: when the file passes MAX_BYTES it is renamed to `<name>.1` (one backup, replacing any
earlier one), so a long-running device cannot fill its disk with outcomes.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger("shield.outcome_log")

DEFAULT_OUTCOME_LOG_PATH = Path.home() / ".xibalba-shield" / "outcomes.jsonl"
MAX_BYTES = 5 * 1024 * 1024


class LocalOutcomeLog:
    def __init__(self, path: str | os.PathLike[str] = DEFAULT_OUTCOME_LOG_PATH, *, max_bytes: int = MAX_BYTES) -> None:
        self.path = Path(path).expanduser()
        self.max_bytes = max_bytes
        self._lock = threading.Lock()

    def __call__(self, outcome: Any) -> None:
        """Sink-compatible: accepts an EnforcementOutcome (or anything with `to_dict`)."""
        self.append(outcome.to_dict() if hasattr(outcome, "to_dict") else dict(outcome))

    def append(self, record: dict[str, Any]) -> bool:
        """Append one record. Returns False (never raises) if it could not be written."""
        line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
                    os.replace(self.path, self.path.with_name(self.path.name + ".1"))
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try:
                    os.write(fd, line.encode("utf-8"))
                finally:
                    os.close(fd)
            return True
        except OSError:
            logger.warning("could not append to local outcome log %s", self.path, exc_info=True)
            return False


def fan_out(*sinks):
    """Return one sink that calls every given sink, isolating failures.

    One sink raising must not stop the others: the backend being down must not stop the local
    log from recording a freeze, and vice versa.
    """
    def _sink(outcome: Any) -> None:
        for sink in sinks:
            try:
                sink(outcome)
            except Exception:  # noqa: BLE001
                logger.exception("an enforcement outcome sink failed")
    return _sink


__all__ = ["DEFAULT_OUTCOME_LOG_PATH", "LocalOutcomeLog", "fan_out"]
