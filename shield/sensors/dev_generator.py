"""
Dev-mode synthetic event generator — NOT a real sensor, and never claims to be one.

Exists so agent_core/policy_engine/integrity_exporter can be built, tested, and demoed end to
end before a real Linux eBPF sensor exists (see sensors/ebpf/README.md for that status). Every
event this produces is synthetic and clearly labeled: `process.exe_path` etc. are fabricated
strings, never real observations of this machine. Do not point this at production policy
decisions and mistake its output for real telemetry — that would be exactly the kind of
silent-mock claim this project's parent repo (`integrity-core`) has a ground rule against.
"""

from __future__ import annotations

import itertools
import random
import time
from typing import Iterator

from ..schemas.events import (
    Activity,
    AgentActivity,
    AgentContext,
    AgentEvent,
    AgentInfo,
    DnsInfo,
    NetworkFlow,
    NetworkFlowInfo,
    NormalizedEvent,
    ProcessActivity,
    ProcessInfo,
)

_SAMPLE_PROCESSES = [
    ("python.exe", "python", 1000, "powershell.exe"),
    ("shadow_ai_tool.exe", "shadow_ai_tool", 1000, "explorer.exe"),
    ("ollama-serve", "ollama-serve", 1, "systemd"),
]
_SAMPLE_AGENTS = ["copilot-agent", "unregistered-llm-tool", "customer-support-bot"]


class DevModeSensor:
    """Synthetic sensor. `interval_sec` between events; `seed` for reproducible test runs.
    `device_id` is threaded through every emitted event so a caller can correlate them
    against a specific `DeviceContext`."""

    def __init__(self, device_id: str, *, interval_sec: float = 1.0, seed: int | None = None):
        self.device_id = device_id
        self.interval_sec = interval_sec
        self._rng = random.Random(seed)
        self._pid_counter = itertools.count(1000)

    def _next_process_event(self) -> ProcessActivity:
        name, base, ppid, parent_name = self._rng.choice(_SAMPLE_PROCESSES)
        return ProcessActivity(
            device_id=self.device_id,
            process=ProcessInfo(
                pid=next(self._pid_counter),
                name=name,
                exe_path=f"/usr/bin/{base}",
                cmdline=f"{name} --dev-mode-synthetic",
                hash_sha256="0" * 64,
                ppid=ppid,
                parent_name=parent_name,
            ),
            activity=Activity(type="launch", severity=self._rng.choice(["low", "medium"])),
        )

    def _next_network_event(self) -> NetworkFlow:
        return NetworkFlow(
            device_id=self.device_id,
            process=ProcessInfo(pid=next(self._pid_counter), name="python.exe"),
            flow=NetworkFlowInfo(
                src_ip="10.0.0.5",
                src_port=self._rng.randint(30000, 60000),
                dst_ip="203.0.113.10",
                dst_port=443,
            ),
            activity=Activity(type="connect", severity="medium"),
            dns=DnsInfo(query_name="dev-mode-synthetic.example", resolved_ips=["203.0.113.10"]),
        )

    def _next_agent_event(self) -> AgentEvent:
        agent_id = self._rng.choice(_SAMPLE_AGENTS)
        return AgentEvent(
            device_id=self.device_id,
            agent=AgentInfo(agent_id=agent_id, name=agent_id, type="llm_tool"),
            context=AgentContext(tools_called=["read_file"], model_endpoint="dev-mode-synthetic"),
            activity=AgentActivity(type="inference", risk_level=self._rng.choice(["low", "medium", "high"])),
        )

    def events(self) -> Iterator[NormalizedEvent]:
        generators = [self._next_process_event, self._next_network_event, self._next_agent_event]
        while True:
            yield self._rng.choice(generators)()
            if self.interval_sec > 0:
                time.sleep(self.interval_sec)

    def one_of_each(self) -> list[NormalizedEvent]:
        """Convenience for tests: one event of each class, no sleep, no randomness in count."""
        return [self._next_process_event(), self._next_network_event(), self._next_agent_event()]
