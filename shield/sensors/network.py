"""
Network sensors — spec/xibalba-shield-v1.md §4.1.

This module provides mock/stub implementations for TCP-connect and DNS-observation sensors,
bridging the integration gap until the real kernel-level implementations (eBPF or uprobe)
are unblocked and completed.

Both sensors structurally satisfy `shield.sensors.base.Sensor` and yield real normalized
event shapes.
"""

from __future__ import annotations

import itertools
import random
import time
from typing import Iterator

from ..schemas.events import (
    Activity,
    DnsInfo,
    NetworkFlow,
    NetworkFlowInfo,
    NormalizedEvent,
    ProcessInfo,
)


class MockTcpConnectSensor:
    """Mock/stub for the TCP-connect sensor.
    Produces synthetic NetworkFlow events representing outbound TCP connections.
    """

    def __init__(self, device_id: str, *, interval_sec: float = 1.0, seed: int | None = None):
        self.device_id = device_id
        self.interval_sec = interval_sec
        self._rng = random.Random(seed)
        self._pid_counter = itertools.count(2000)

    def _next_event(self) -> NetworkFlow:
        return NetworkFlow(
            device_id=self.device_id,
            process=ProcessInfo(pid=next(self._pid_counter), name="mock_agent.exe"),
            flow=NetworkFlowInfo(
                src_ip="192.168.1.100",
                src_port=self._rng.randint(1024, 65535),
                dst_ip=f"{self._rng.randint(1, 255)}.{self._rng.randint(0, 255)}.{self._rng.randint(0, 255)}.{self._rng.randint(0, 255)}",
                dst_port=self._rng.choice([80, 443, 8080]),
                protocol="tcp",
                direction="outbound",
            ),
            activity=Activity(type="connect", severity="low", outcome="success"),
            dns=DnsInfo(),
        )

    def events(self) -> Iterator[NormalizedEvent]:
        while True:
            yield self._next_event()
            if self.interval_sec > 0:
                time.sleep(self.interval_sec)

    def poll(self, timeout_ms: int = 1000) -> list[NetworkFlow]:
        """Provides a finite polling capability similar to real sensors."""
        time.sleep(min(timeout_ms / 1000.0, self.interval_sec if self.interval_sec > 0 else 0))
        return [self._next_event()]


class MockDnsObservationSensor:
    """Mock/stub for the DNS observation sensor.
    Produces synthetic NetworkFlow events representing DNS queries and responses.
    """

    def __init__(self, device_id: str, *, interval_sec: float = 1.0, seed: int | None = None):
        self.device_id = device_id
        self.interval_sec = interval_sec
        self._rng = random.Random(seed)
        self._pid_counter = itertools.count(3000)

    def _next_event(self) -> NetworkFlow:
        query = self._rng.choice(["api.shadow-llm.test", "metrics.telemetry.local", "auth.backend.internal"])
        resolved_ip = f"{self._rng.randint(1, 255)}.{self._rng.randint(0, 255)}.{self._rng.randint(0, 255)}.{self._rng.randint(0, 255)}"
        return NetworkFlow(
            device_id=self.device_id,
            process=ProcessInfo(pid=next(self._pid_counter), name="dns_client.exe"),
            flow=NetworkFlowInfo(
                src_ip="192.168.1.100",
                src_port=self._rng.randint(1024, 65535),
                dst_ip="8.8.8.8",
                dst_port=53,
                protocol="udp",
                direction="outbound",
            ),
            activity=Activity(type="dns_query", severity="low", outcome="success"),
            dns=DnsInfo(query_name=query, resolved_ips=[resolved_ip]),
        )

    def events(self) -> Iterator[NormalizedEvent]:
        while True:
            yield self._next_event()
            if self.interval_sec > 0:
                time.sleep(self.interval_sec)

    def poll(self, timeout_ms: int = 1000) -> list[NetworkFlow]:
        """Provides a finite polling capability similar to real sensors."""
        time.sleep(min(timeout_ms / 1000.0, self.interval_sec if self.interval_sec > 0 else 0))
        return [self._next_event()]
