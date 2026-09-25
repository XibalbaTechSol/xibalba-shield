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
from datetime import datetime, timezone
from typing import Iterator

from ..schemas.events import (
    Activity,
    AgentActivity,
    AgentContext,
    AgentEvent,
    AgentInfo,
    DnsInfo,
    FileActivity,
    FileInfo,
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

    def __init__(self, device_id: str, *, interval_sec: float = 1.0, seed: int | None = None,
                 policy_scenario: str | None = None):
        self.device_id = device_id
        self.interval_sec = interval_sec
        self._rng = random.Random(seed)
        self._pid_counter = itertools.count(1000)
        self._last_event_at: str | None = None
        self.policy_scenario = policy_scenario

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

    def policy_fixtures(self) -> list[NormalizedEvent]:
        """Return safe, explicitly development-only events that exercise live routing.

        These are not kernel observations. They exist for validating the complete
        sensor -> EventRouter -> policy -> decision sink -> UI path without touching a
        real workload. Callers must use ``--no-containment`` for these fake PIDs.
        """
        if self.policy_scenario == "smb":
            return [
                ProcessActivity(
                    device_id=self.device_id,
                    process=ProcessInfo(pid=next(self._pid_counter), name="policy-fixture",
                                        exe_path="/opt/ai/shadow-agent/run"),
                    activity=Activity(type="launch", severity="medium"),
                ),
                ProcessActivity(
                    device_id=self.device_id,
                    process=ProcessInfo(pid=next(self._pid_counter), name="policy-fixture",
                                        exe_path="/opt/llm-tools/model-runner"),
                    activity=Activity(type="launch", severity="medium"),
                ),
                AgentEvent(
                    device_id=self.device_id,
                    agent=AgentInfo(agent_id="did:test:unregistered", name="policy-fixture-agent"),
                    context=AgentContext(tools_called=["read_file"]),
                    activity=AgentActivity(type="inference", risk_level="high"),
                ),
                FileActivity(
                    device_id=self.device_id,
                    process=ProcessInfo(pid=next(self._pid_counter), name="policy-fixture"),
                    file=FileInfo(path="/etc/shield/policy-test", name="policy-test"),
                    activity=Activity(type="write", severity="high"),
                ),
                FileActivity(
                    device_id=self.device_id,
                    process=ProcessInfo(pid=next(self._pid_counter), name="policy-fixture"),
                    file=FileInfo(path="/home/test/.ssh/authorized_keys", name="authorized_keys"),
                    activity=Activity(type="write", severity="high"),
                ),
            ]
        if self.policy_scenario == "professional-services":
            return [
                AgentEvent(
                    device_id=self.device_id,
                    agent=AgentInfo(agent_id="did:test:unregistered", name="policy-fixture-agent"),
                    context=AgentContext(tools_called=["read_file"]),
                    activity=AgentActivity(type="inference", risk_level="high"),
                ),
                AgentEvent(
                    device_id=self.device_id,
                    agent=AgentInfo(agent_id="did:test:unapproved-routing", name="policy-fixture-agent"),
                    context=AgentContext(model_endpoint="https://unapproved.example/model"),
                    activity=AgentActivity(type="inference", risk_level="high"),
                ),
                AgentEvent(
                    device_id=self.device_id,
                    agent=AgentInfo(agent_id="did:test:client-context", name="policy-fixture-agent"),
                    context=AgentContext(data_sources=["customer_records"]),
                    activity=AgentActivity(type="inference", risk_level="high"),
                ),
                AgentEvent(
                    device_id=self.device_id,
                    agent=AgentInfo(agent_id="did:test:financial-context", name="policy-fixture-agent"),
                    context=AgentContext(data_sources=["financial_docs"]),
                    activity=AgentActivity(type="inference", risk_level="high"),
                ),
            ]
        if self.policy_scenario == "regulated":
            return [
                AgentEvent(
                    device_id=self.device_id,
                    agent=AgentInfo(agent_id="did:test:unregistered", name="policy-fixture-agent"),
                    context=AgentContext(tools_called=["read_file"]),
                    activity=AgentActivity(type="inference", risk_level="high"),
                ),
                AgentEvent(
                    device_id=self.device_id,
                    agent=AgentInfo(agent_id="did:test:high-risk-output", name="policy-fixture-agent"),
                    context=AgentContext(tools_called=["publish_output"]),
                    activity=AgentActivity(type="output", risk_level="high"),
                ),
                AgentEvent(
                    device_id=self.device_id,
                    agent=AgentInfo(agent_id="did:test:phi-context", name="policy-fixture-agent"),
                    context=AgentContext(data_sources=["patient_record"]),
                    activity=AgentActivity(type="inference", risk_level="high"),
                ),
                FileActivity(
                    device_id=self.device_id,
                    process=ProcessInfo(pid=next(self._pid_counter), name="policy-fixture"),
                    file=FileInfo(path="/etc/shield/policy-test", name="policy-test"),
                    activity=Activity(type="write", severity="high"),
                ),
            ]
        return []

    def events(self) -> Iterator[NormalizedEvent]:
        if self.policy_scenario:
            fixtures = self.policy_fixtures()
            if not fixtures:
                raise ValueError(f"unknown policy scenario {self.policy_scenario!r}")
            while True:
                for event in fixtures:
                    self._last_event_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                    yield event
                    if self.interval_sec > 0:
                        time.sleep(self.interval_sec)

        generators = [self._next_process_event, self._next_network_event, self._next_agent_event]
        while True:
            self._last_event_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            yield self._rng.choice(generators)()
            if self.interval_sec > 0:
                time.sleep(self.interval_sec)

    def one_of_each(self) -> list[NormalizedEvent]:
        """Convenience for tests: one event of each class, no sleep, no randomness in count."""
        return [self._next_process_event(), self._next_network_event(), self._next_agent_event()]

    def health(self) -> dict:
        """Always healthy -- synthetic, never claims to observe real attach/loss state."""
        return {"attached": True, "lost_events": 0, "last_event_at": self._last_event_at}
