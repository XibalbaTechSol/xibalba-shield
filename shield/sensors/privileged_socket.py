"""Unprivileged client for the root-owned eBPF probe bridge."""
from __future__ import annotations

import json
import socket
import time
from collections.abc import Iterator

from ..schemas.events import Activity, ProcessActivity, ProcessInfo


class PrivilegedProcessSensor:
    def __init__(self, socket_path: str, reconnect_sec: float = 1.0):
        self.socket_path = socket_path
        self.reconnect_sec = reconnect_sec
        self._lost_events = 0
        self._last_event_at: str | None = None
        self._last_heartbeat_at: str | None = None
        self._attached = False

    def health(self) -> dict:
        return {
            "attached": self._attached,
            "attach_mode": "privileged-helper",
            "lost_events": self._lost_events,
            "last_event_at": self._last_event_at,
            "last_heartbeat_at": self._last_heartbeat_at,
        }

    def _connect(self) -> socket.socket:
        while True:
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(self.socket_path)
                self._attached = True
                return sock
            except OSError:
                self._attached = False
                time.sleep(self.reconnect_sec)

    def events(self) -> Iterator[ProcessActivity]:
        while True:
            try:
                with self._connect() as sock, sock.makefile("r", encoding="utf-8") as stream:
                    for line in stream:
                        try:
                            raw = json.loads(line)
                            if raw.get("type") == "heartbeat":
                                self._last_heartbeat_at = raw.get("time")
                                self._attached = True
                                continue
                            if raw.get("type") != "process_activity":
                                continue
                            event = raw["event"]
                            self._last_event_at = event.get("time")
                            yield ProcessActivity(
                                device_id=event["device_id"],
                                tenant_id=event.get("tenant_id", ""),
                                time=event.get("time") or "",
                                process=ProcessInfo(**event["process"]),
                                activity=Activity(**event["activity"]),
                            )
                        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                            self._lost_events += 1
            except OSError:
                self._attached = False
                time.sleep(self.reconnect_sec)
