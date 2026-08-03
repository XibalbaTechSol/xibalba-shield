"""
Agent Core state — spec/xibalba-shield-v1.md §4.2.

`DeviceContext` + `AgentRegistry` are owned by the single long-lived agent-core process on
each device. The registry IS Shield's shadow-AI-discovery mechanism: an agent with no entry
here is, by definition, unregistered (spec §4.2) — the policy engine's "registered" condition
(policy_engine/engine.py) reads straight off this registry, not a separate discovery pass.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass(frozen=True)
class DeviceContext:
    device_id: str
    tenant_id: str = ""
    os: str = ""
    device_role: str = ""


@dataclass
class RegisteredAgent:
    agent_id: str
    name: str
    owner_user_id: str = ""
    purpose: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)


class AgentRegistry:
    """Every AI agent/tool/model API observed on the device. Thread-safe: sensor callbacks
    and the CLI's `shield status` read path can both touch this concurrently."""

    def __init__(self) -> None:
        self._agents: dict[str, RegisteredAgent] = {}
        self._lock = threading.Lock()

    def register(self, agent_id: str, name: str, *, owner_user_id: str = "", purpose: str = "") -> RegisteredAgent:
        with self._lock:
            existing = self._agents.get(agent_id)
            if existing:
                existing.last_seen = time.time()
                return existing
            agent = RegisteredAgent(agent_id=agent_id, name=name, owner_user_id=owner_user_id, purpose=purpose)
            self._agents[agent_id] = agent
            return agent

    def touch(self, agent_id: str) -> None:
        """Record that a REGISTERED agent was observed again, without registering an
        unknown one — that distinction is what lets the policy engine's `registered: false`
        condition (spec §4.2/§7) actually mean something."""
        with self._lock:
            agent = self._agents.get(agent_id)
            if agent:
                agent.last_seen = time.time()

    def is_registered(self, agent_id: str) -> bool:
        with self._lock:
            return agent_id in self._agents

    def registered_ids(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._agents.keys())

    def all_agents(self) -> list[RegisteredAgent]:
        with self._lock:
            return list(self._agents.values())
