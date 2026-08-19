"""
Canonical event shapes — spec/xibalba-shield-v1.md §5, in the parent `integrity-core` repo.

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
class PolicyRef:
    version: str = ""
    hash: str = ""


@dataclass
class Decision:
    action: Literal["allow", "deny", "contain", "log_only", "escalate"]
    reason: str = ""
    severity: Literal["low", "medium", "high", "critical"] = "low"
    # docs/design/2026-08-18-a2a-escalation-schema-proposal.md: which tier actually produced
    # this action, so an exported/audited/SIEM-consumed decision is self-describing rather
    # than requiring log correlation to reconstruct whether Tier 1 resolved it, Tier 2 revised
    # it, or Tier 2 was asked and remained unable to resolve it (see `router.py`'s handle()).
    # Default "tier1" matches existing behavior for any pre-existing Decision(...) call site
    # that doesn't set this explicitly -- Tier 1 is the first (and, until now, often only)
    # evaluator every event sees.
    tier: Literal["tier1", "tier2", "tier2_unresolved"] = "tier1"


@dataclass
class ExportStatus:
    attempted: bool = False
    event_exported: bool = False
    decision_exported: bool = False
    authorized: bool | None = None
    reason: str = ""
    verification_token: str | None = None
    batch_index: int | None = None
    agent_id: str | None = None
    nonce: int | None = None
    intended_state_hash: str | None = None


@dataclass
class PolicyDecision:
    """§5.5 — what the Policy Engine (shield/policy_engine) produces for EVERY evaluation,
    not just denials. This is what shield/integrity_exporter turns into a signed BCC
    commitment (§4.5)."""

    device_id: str
    event_ref: EventRef
    rule: RuleRef
    decision: Decision
    policy: PolicyRef = field(default_factory=PolicyRef)
    export: ExportStatus = field(default_factory=ExportStatus)
    time: str = field(default_factory=_now_iso)
    klass: str = field(default="policy_decision", init=False)

    def to_dict(self) -> dict[str, Any]:
        out = {
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
        if self.policy.version or self.policy.hash:
            out["policy"] = vars(self.policy)
        if self.export.attempted or self.export.reason:
            out["export"] = vars(self.export)
        return out


@dataclass
class EscalationRequest:
    """docs/design/2026-08-18-a2a-escalation-schema-proposal.md — what a Tier-2-still-
    uncertain event carries if/when it escalates to a future Tier 3. Carries the FULL
    decision trail (Tier 1's original decision, Tier 2's revision), not just the final
    outcome — an auditor or a future cloud model needs to see what already ran and what
    each tier concluded, not just "still escalate"."""

    event: Any  # NormalizedEvent (Any to avoid a forward-reference cycle with events below)
    tier1_decision: Decision
    tier2_decision: Decision
    reason: str = ""
    time: str = field(default_factory=_now_iso)


@dataclass
class EscalationResponse:
    """Mirrors PolicyDecision's decision-bearing shape closely enough that a future Tier-3
    backend can be a drop-in `evaluate()`-shaped call, the same convention
    `shield/agent_core/slm_backend.py`'s `SlmBackend` protocol already establishes for Tier 2
    (`evaluate(event, ctx) -> PolicyDecision`). Not yet produced by any real code — no Tier 3
    exists (docs/design/2026-08-18-a2a-escalation-schema-proposal.md's explicit deferral) —
    this shape exists so a future Tier3Backend has a real contract to implement against."""

    decision: Decision
    reason: str = ""
    time: str = field(default_factory=_now_iso)


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
