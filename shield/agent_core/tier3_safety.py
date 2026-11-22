"""Bounded Tier 3 response storage and release safety primitives."""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable

from shield.schemas.events import EscalationResponse, ProcessInfo


@dataclass(frozen=True)
class AdjudicationRecord:
    response: EscalationResponse
    recorded_at: float


class BoundedAdjudicationStore:
    """Thread-safe bounded memory store; oldest responses are evicted deterministically."""
    def __init__(self, max_records: int = 1024) -> None:
        if not isinstance(max_records, int) or isinstance(max_records, bool) or max_records < 1:
            raise ValueError("max_records must be a positive int")
        self._records: deque[AdjudicationRecord] = deque(maxlen=max_records)
        self._lock = threading.Lock()

    def record(self, response: EscalationResponse) -> None:
        with self._lock:
            self._records.append(AdjudicationRecord(response, time.time()))

    def snapshot(self) -> tuple[AdjudicationRecord, ...]:
        with self._lock:
            return tuple(self._records)


class Tier3DispatchGate:
    """Bound concurrent and rolling-window dispatches; excess work is rejected."""
    def __init__(self, max_inflight: int = 2, max_per_window: int = 32, window_seconds: float = 60.0) -> None:
        if min(max_inflight, max_per_window) < 1 or window_seconds <= 0:
            raise ValueError("dispatch limits must be positive")
        self._semaphore = threading.BoundedSemaphore(max_inflight)
        self._max = max_per_window
        self._window = window_seconds
        self._times: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self) -> bool:
        now = time.monotonic()
        with self._lock:
            while self._times and now - self._times[0] >= self._window:
                self._times.popleft()
            if len(self._times) >= self._max:
                return False
            if not self._semaphore.acquire(blocking=False):
                return False
            self._times.append(now)
            return True

    def release(self) -> None:
        self._semaphore.release()


def process_identity_matches(expected: ProcessInfo, actual: ProcessInfo) -> bool:
    """Require PID plus available start/cgroup identity before any future resume action."""
    if expected.pid != actual.pid:
        return False
    if expected.start_time and actual.start_time != expected.start_time:
        return False
    if expected.cgroup_id and actual.cgroup_id != expected.cgroup_id:
        return False
    return bool(expected.start_time or expected.cgroup_id)


def verified_resume(broker: object, expected: ProcessInfo, read_identity: Callable[[int], ProcessInfo]):
    """Resume only when a fresh PID identity matches; otherwise fail closed."""
    actual = read_identity(expected.pid)
    if not process_identity_matches(expected, actual):
        raise RuntimeError("refusing resume: PID identity changed or is unverifiable")
    return broker.resume(expected.pid)
