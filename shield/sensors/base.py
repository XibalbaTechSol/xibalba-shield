"""
Sensor interface — spec/xibalba-shield-v1.md §4.1.

Real interface, real contract: a Sensor yields already-normalized events (schemas/events.py)
and owns no policy logic and makes no enforcement decisions (that's the Policy Engine's job,
kept separate so a sensor bug can never itself become a false-enforcement bug — §4.1's own
stated reason for this split).

Implementations exist as of this writing:
  - `dev_generator.DevModeSensor` — REAL, synthetic events for testing the rest of the
    pipeline end-to-end. Explicitly not a claim of real telemetry.
  - `ebpf/` — real Linux probe implementations. Process-exec and file-write have historical
    live verification; TCP-connect remains blocked by BCC/kernel compatibility. See that
    directory's README for the exact status.
"""

from __future__ import annotations

from typing import Iterator, Protocol

from ..schemas.events import NormalizedEvent


class Sensor(Protocol):
    def events(self) -> Iterator[NormalizedEvent]:
        """Yield normalized events as they occur. Implementations decide their own blocking/
        polling strategy; callers (agent_core.router) just iterate."""
        ...

    def health(self) -> dict:
        """Return `{"attached": bool, "lost_events": int, "last_event_at": str | None}` —
        watchdog telemetry, not enforcement input. Structural, like the rest of this
        Protocol: a caller should use `getattr(sensor, "health", None)` rather than assume
        every implementation defines it."""
        ...
