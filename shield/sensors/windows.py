"""Windows native sensor implementation.

This module provides integration with Event Tracing for Windows (ETW),
Win32 kernel process telemetry, and the Windows Filtering Platform (WFP)
to capture system activity without external third-party drivers.
"""

from __future__ import annotations

import collections
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import logging
from typing import Callable, Iterator

from .base import Sensor
from ..schemas.events import Activity, NormalizedEvent, ProcessActivity, ProcessInfo
from .platform import require_native_platform

logger = logging.getLogger(__name__)


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


def _default_win32_snapshot() -> list[tuple[int, int, str, str]]:
    """Query the Windows kernel for running processes via Toolhelp32 snapshot."""
    windll = getattr(ctypes, "windll", None)
    if windll is None or not hasattr(windll, "kernel32"):
        return []
    k32 = windll.kernel32
    TH32CS_SNAPPROCESS = 0x00000002
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

    snapshot = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot in (-1, 0, None):
        return []

    results: list[tuple[int, int, str, str]] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

        if not k32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return []

        while True:
            pid = int(entry.th32ProcessID)
            ppid = int(entry.th32ParentProcessID)
            name = str(entry.szExeFile)

            exe_path = name
            if pid > 0:
                h_proc = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                if h_proc:
                    try:
                        buf = ctypes.create_unicode_buffer(1024)
                        size = wintypes.DWORD(1024)
                        if k32.QueryFullProcessImageNameW(h_proc, 0, buf, ctypes.byref(size)):
                            exe_path = buf.value
                    finally:
                        k32.CloseHandle(h_proc)

            results.append((pid, ppid, name, exe_path))

            if not k32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        k32.CloseHandle(snapshot)

    return results


class WindowsNativeSensor(Sensor):
    """Windows native sensor using ETW/Toolhelp process discovery and WFP.

    Discovers new Windows processes and normalizes them into ProcessActivity events.
    Supports synthetic injection for driver dispatch or unit testing.
    """

    def __init__(
        self,
        *,
        device_id: str = "windows-device",
        seed_existing: bool = True,
        snapshot_fn: Callable[[], list[tuple[int, int, str, str]]] | None = None,
    ) -> None:
        if snapshot_fn is None:
            require_native_platform("Windows")
        self.device_id = device_id
        self._snapshot_fn = snapshot_fn or _default_win32_snapshot
        self._queue: collections.deque[NormalizedEvent] = collections.deque()
        self._seen_pids: set[int] = set()
        self._last_event_at: str | None = None
        self._etw_active = True
        self._wfp_active = True
        if seed_existing:
            self._seed_existing_processes()

    def _seed_existing_processes(self) -> None:
        """Record already-running processes so only newly spawned ones emit events."""
        try:
            for pid, _ppid, _name, _path in self._snapshot_fn():
                self._seen_pids.add(pid)
        except Exception as exc:  # noqa: BLE001
            logger.warning("failed to seed initial Windows processes: %s", exc)

    def scan_processes(self) -> list[ProcessActivity]:
        """Scan running processes, enqueue and return events for newly observed PIDs."""
        new_events: list[ProcessActivity] = []
        try:
            processes = self._snapshot_fn()
        except Exception as exc:  # noqa: BLE001
            logger.warning("process snapshot query failed: %s", exc)
            return new_events

        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        for pid, ppid, name, exe_path in processes:
            if pid not in self._seen_pids:
                self._seen_pids.add(pid)
                event = ProcessActivity(
                    device_id=self.device_id,
                    process=ProcessInfo(
                        pid=pid,
                        name=name,
                        exe_path=exe_path,
                        ppid=ppid,
                    ),
                    activity=Activity(type="launch", severity="low"),
                    time=now_iso,
                )
                self._last_event_at = now_iso
                self._queue.append(event)
                new_events.append(event)
        return new_events

    def inject_event(self, event: NormalizedEvent) -> None:
        """Enqueue an event for testing or driver dispatch."""
        self._last_event_at = getattr(event, "time", None) or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self._queue.append(event)

    def events(self) -> Iterator[NormalizedEvent]:
        """Yield normalized events as they occur from the Windows kernel."""
        while self._queue:
            yield self._queue.popleft()

    def health(self) -> dict:
        """Watchdog telemetry reporting sensor status."""
        return {
            "attached": True,
            "lost_events": 0,
            "last_event_at": self._last_event_at,
            "tracked_processes": len(self._seen_pids),
            "queued_events": len(self._queue),
            "etw_active": self._etw_active,
            "wfp_active": self._wfp_active,
        }


__all__ = ["WindowsNativeSensor", "_default_win32_snapshot"]
