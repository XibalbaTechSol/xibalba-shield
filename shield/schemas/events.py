"""
Canonical event shapes — spec/xibalba-shield-v1.md §5, in the parent `integrity-latest` repo.

OCSF-style JSON, chosen there for SIEM/SOAR portability. These are the canonical shapes; per
that spec, a package implementing them MUST NOT rename fields — the same discipline
`docs/INTERFACE_CONTRACT.md` already applies to the BCC commitment shape in the parent repo.

Every class here is a real, tested normalization target — nothing about the schemas themselves
is `[PLANNED]`. What IS still `[PLANNED]` is the sensor that produces real instances of them
(see `shield/sensors/`).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Literal


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class Activity:
    type: str
    severity: Literal["low", "medium", "high", "critical"] = "low"
    outcome: str = "success"


@dataclass
class ProcessInfo:
    pid: int
    name: str
    exe_path: str = ""
    cmdline: str = ""
    hash_sha256: str = ""
    ppid: int = 0
    parent_name: str = ""


@dataclass
class ProcessActivity:
    """§5.1"""

    device_id: str
    process: ProcessInfo
    activity: Activity
    tenant_id: str = ""
    time: str = field(default_factory=_now_iso)
    klass: str = field(default="process_activity", init=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "class": self.klass,
            "time": self.time,
            "device_id": self.device_id,
            "tenant_id": self.tenant_id,
            "process": vars(self.process),
            "activity": vars(self.activity),
        }


@dataclass
class FileInfo:
    path: str
    name: str
    ext: str = ""
    type: str = "file"


@dataclass
class FileActivity:
    """§5.2"""

    device_id: str
    process: ProcessInfo
    file: FileInfo
    activity: Activity
    time: str = field(default_factory=_now_iso)
    klass: str = field(default="file_activity", init=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "class": self.klass,
            "time": self.time,
            "device_id": self.device_id,
            "process": {"pid": self.process.pid, "name": self.process.name},
            "file": vars(self.file),
            "activity": vars(self.activity),
        }


@dataclass
class NetworkFlowInfo:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str = "tcp"
    direction: Literal["inbound", "outbound"] = "outbound"


@dataclass
class DnsInfo:
    query_name: str = ""
    resolved_ips: list[str] = field(default_factory=list)


@dataclass
class NetworkFlow:
    """§5.3"""

    device_id: str
    process: ProcessInfo
    flow: NetworkFlowInfo
    activity: Activity
    dns: DnsInfo = field(default_factory=DnsInfo)
    time: str = field(default_factory=_now_iso)
    klass: str = field(default="network_flow", init=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "class": self.klass,
            "time": self.time,
            "device_id": self.device_id,
            "process": {"pid": self.process.pid, "name": self.process.name},
            "flow": vars(self.flow),
            "activity": vars(self.activity),
            "dns": vars(self.dns),
        }


@dataclass
class AgentInfo:
    agent_id: str
    name: str = ""
    type: str = "llm_tool"
    owner_user_id: str = ""
    workload_id: str = ""


@dataclass
class AgentContext:
    data_sources: list[str] = field(default_factory=list)
    tools_called: list[str] = field(default_factory=list)
    model_endpoint: str = ""


@dataclass
class AgentActivity:
    type: str
    risk_level: Literal["low", "medium", "high", "critical"] = "low"
    policy_violation: bool = False


@dataclass
class AgentEvent:
    """§5.4 — a discovered/observed AI agent or tool boundary crossing."""

    device_id: str
    agent: AgentInfo
    context: AgentContext
    activity: AgentActivity
    time: str = field(default_factory=_now_iso)
    klass: str = field(default="agent_event", init=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "class": self.klass,
            "time": self.time,
            "device_id": self.device_id,
            "agent": vars(self.agent),
            "context": vars(self.context),
            "activity": vars(self.activity),
        }


@dataclass
class EventRef:
    klass: str
    event_id: str


@dataclass
class RuleRef:
    rule_id: str
    name: str
    version: str


@dataclass
class Decision:
    action: Literal["allow", "deny", "contain", "log_only", "escalate"]
    reason: str = ""
    severity: Literal["low", "medium", "high", "critical"] = "low"


@dataclass
class PolicyDecision:
    """§5.5 — what the Policy Engine (shield/policy_engine) produces for EVERY evaluation,
    not just denials. This is what shield/integrity_exporter turns into a signed BCC
    commitment (§4.5)."""

    device_id: str
    event_ref: EventRef
    rule: RuleRef
    decision: Decision
    time: str = field(default_factory=_now_iso)
    klass: str = field(default="policy_decision", init=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "class": self.klass,
            "time": self.time,
            "device_id": self.device_id,
            # §5.5's canonical shape names this field "class", but the Python attribute is
            # `klass` (a bare `class` attribute isn't legal) -- vars() would emit the wrong
            # wire key here, the same reason the top-level classes below map `self.klass` to
            # "class" explicitly instead of using vars() for themselves.
            "event_ref": {"class": self.event_ref.klass, "event_id": self.event_ref.event_id},
            "rule": vars(self.rule),
            "decision": vars(self.decision),
        }


# §5.6 — security-event intent_type namespace. Extends BCC Commitment.intent_type the same
# way healthcare/financial types do (protocol spec §21.2) — zero schema change required,
# the field already accepts any string.
INTENT_TYPES = {
    "shadow_agent_detected": "An unregistered agent/tool was discovered",
    "agent_contained": "An agent process was contained/terminated by policy",
    "connection_blocked": "An outbound connection was denied",
    "guardrail_denied": "An LLM/agent boundary hook denied an inference or tool call",
    "phi_access_attempt": "A PHI-bearing resource was accessed or an access was attempted",
    "device_posture_change": "A device's risk posture crossed a policy-relevant threshold",
}

NormalizedEvent = ProcessActivity | FileActivity | NetworkFlow | AgentEvent
