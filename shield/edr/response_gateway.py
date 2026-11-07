"""Hash-bound authorization of EDR response actions.

This is the response-action counterpart of :mod:`shield.transaction_gateway`. A caller (an
analyst, a SOAR playbook, or an AI agent) submits a *response intent* -- "contain this host",
"kill this process" -- and receives a deterministic ``allow`` / ``deny`` / ``escalate``
decision bound to the SHA-256 hash of the canonical intent.

The gateway decides; it never executes. Execution happens only in
:meth:`shield.edr.provider.EndpointProvider.execute`, which refuses to run without an
authorization whose intent hash matches the action it is asked to perform.

Severity used by the ``auto_allow_critical`` setting must come from a detection the server
fetched from the EDR itself (``verified_detection``), never from caller-supplied fields.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from ..canonical import canonical_bytes

Decision = Literal["allow", "deny", "escalate"]

RESPONSE_ACTIONS = frozenset(
    {"contain_host", "lift_containment", "kill_process", "quarantine_file", "rtr_command", "policy_change"}
)
ACTOR_TYPES = frozenset({"human", "agent", "soar"})
AGENT_CONTAIN_HOST_MODES = frozenset({"always_escalate", "auto_allow_critical", "deny"})

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RTR_BASE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_MAX_JUSTIFICATION = 2000


@dataclass(frozen=True)
class ResponseIntent:
    tenant_id: str
    request_id: str
    actor_type: str
    actor_id: str
    vendor: str
    host_id: str
    action: str
    justification: str
    params: dict[str, Any] = field(default_factory=dict)
    actor_did: str | None = None
    detection_id: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ResponseIntent":
        if not isinstance(raw, dict):
            raise ValueError("response intent must be an object")
        required = ("tenant_id", "request_id", "actor_type", "actor_id", "vendor", "host_id", "action", "justification")
        missing = [key for key in required if key not in raw]
        if missing:
            raise ValueError(f"missing response intent fields: {', '.join(missing)}")
        params = raw.get("params") or {}
        if not isinstance(params, dict):
            raise ValueError("params must be an object")
        intent = cls(
            tenant_id=str(raw["tenant_id"]).strip(),
            request_id=str(raw["request_id"]).strip(),
            actor_type=str(raw["actor_type"]).strip().lower(),
            actor_id=str(raw["actor_id"]).strip(),
            vendor=str(raw["vendor"]).strip().lower(),
            host_id=str(raw["host_id"]).strip(),
            action=str(raw["action"]).strip().lower(),
            justification=str(raw["justification"]).strip(),
            params=_normalize_params(str(raw["action"]).strip().lower(), params),
            actor_did=str(raw["actor_did"]).strip() if raw.get("actor_did") else None,
            detection_id=str(raw["detection_id"]).strip() if raw.get("detection_id") else None,
        )
        intent.validate()
        return intent

    def validate(self) -> None:
        for name in ("tenant_id", "request_id", "actor_id", "vendor", "host_id"):
            if not _ID.fullmatch(getattr(self, name)):
                raise ValueError(f"{name} must be a non-empty identifier")
        if self.detection_id is not None and not _ID.fullmatch(self.detection_id):
            raise ValueError("detection_id must be an identifier")
        if self.actor_type not in ACTOR_TYPES:
            raise ValueError(f"actor_type must be one of: {', '.join(sorted(ACTOR_TYPES))}")
        if self.action not in RESPONSE_ACTIONS:
            raise ValueError(f"action must be one of: {', '.join(sorted(RESPONSE_ACTIONS))}")
        if not self.justification:
            raise ValueError("justification must not be empty")
        if len(self.justification) > _MAX_JUSTIFICATION:
            raise ValueError(f"justification must be at most {_MAX_JUSTIFICATION} characters")
        if self.actor_type == "agent" and not self.actor_did:
            raise ValueError("agent actors must present an actor_did")
        _normalize_params(self.action, self.params)

    def canonical(self) -> dict[str, Any]:
        return asdict(self)

    def intent_hash(self) -> str:
        return "sha256:" + hashlib.sha256(canonical_bytes(self.canonical())).hexdigest()


def _normalize_params(action: str, params: dict[str, Any]) -> dict[str, Any]:
    """Return the only parameters an action accepts, validated. Unknown keys are rejected."""
    allowed: dict[str, tuple[str, ...]] = {
        "contain_host": (),
        "lift_containment": (),
        "kill_process": ("pid",),
        "quarantine_file": ("sha256",),
        "rtr_command": ("base_command", "command_string"),
        "policy_change": ("policy_id", "change"),
    }
    expected = allowed.get(action)
    if expected is None:
        raise ValueError(f"action must be one of: {', '.join(sorted(RESPONSE_ACTIONS))}")
    unknown = sorted(set(params) - set(expected))
    if unknown:
        raise ValueError(f"unexpected params for {action}: {', '.join(unknown)}")
    missing = [key for key in expected if key not in params]
    if missing:
        raise ValueError(f"missing params for {action}: {', '.join(missing)}")
    out: dict[str, Any] = {}
    if action == "kill_process":
        pid = params["pid"]
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError("pid must be a positive integer")
        out["pid"] = pid
    elif action == "quarantine_file":
        digest = str(params["sha256"]).lower()
        if not _SHA256.fullmatch(digest):
            raise ValueError("sha256 must be 64 hexadecimal characters")
        out["sha256"] = digest
    elif action == "rtr_command":
        base = str(params["base_command"]).strip().lower()
        command = str(params["command_string"]).strip()
        if not _RTR_BASE.fullmatch(base):
            raise ValueError("base_command must be a single lowercase command word")
        if not command or command.split()[0].lower() != base:
            raise ValueError("command_string must begin with base_command")
        if len(command) > 512 or any(ch in command for ch in "\n\r\x00"):
            raise ValueError("command_string must be a single line of at most 512 characters")
        out["base_command"] = base
        out["command_string"] = command
    elif action == "policy_change":
        policy_id = str(params["policy_id"]).strip()
        if not _ID.fullmatch(policy_id):
            raise ValueError("policy_id must be an identifier")
        if not isinstance(params["change"], dict) or not params["change"]:
            raise ValueError("change must be a non-empty object")
        out["policy_id"] = policy_id
        out["change"] = params["change"]
    return out


@dataclass(frozen=True)
class ResponsePolicy:
    """Tenant response policy. Defaults are deliberately conservative.

    ``agent_contain_host`` is the operator-facing Settings control for agent-initiated host
    containment: ``always_escalate`` (default), ``auto_allow_critical`` (allow only when the
    server-verified detection on the same host is Critical), or ``deny``.
    """

    agent_contain_host: str = "always_escalate"
    escalate_actions: frozenset[str] = frozenset(
        {"contain_host", "lift_containment", "kill_process", "rtr_command", "policy_change"}
    )
    agent_auto_allow_actions: frozenset[str] = frozenset()
    agent_denied_actions: frozenset[str] = frozenset({"policy_change"})
    rtr_allowed_base_commands: frozenset[str] = frozenset()
    two_person_actions: frozenset[str] = frozenset({"lift_containment", "policy_change"})
    approval_ttl_seconds: int = 900
    enabled_vendors: frozenset[str] = frozenset({"crowdstrike", "simulated"})
    policy_version: str = "tenant-edr-v1"

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "ResponsePolicy":
        raw = dict(raw or {})
        defaults = cls()
        unknown = sorted(set(raw) - set(defaults.__dataclass_fields__))
        if unknown:
            raise ValueError(f"unknown response policy fields: {', '.join(unknown)}")

        def actions(name: str) -> frozenset[str]:
            if name not in raw:
                return getattr(defaults, name)
            values = frozenset(str(v).strip().lower() for v in raw[name])
            bad = sorted(values - RESPONSE_ACTIONS)
            if bad:
                raise ValueError(f"{name} contains unknown actions: {', '.join(bad)}")
            return values

        mode = str(raw.get("agent_contain_host", defaults.agent_contain_host)).strip().lower()
        if mode not in AGENT_CONTAIN_HOST_MODES:
            raise ValueError(f"agent_contain_host must be one of: {', '.join(sorted(AGENT_CONTAIN_HOST_MODES))}")
        ttl = raw.get("approval_ttl_seconds", defaults.approval_ttl_seconds)
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not 60 <= ttl <= 86_400:
            raise ValueError("approval_ttl_seconds must be an integer between 60 and 86400")
        rtr = frozenset(str(v).strip().lower() for v in raw.get("rtr_allowed_base_commands", ()))
        if any(not _RTR_BASE.fullmatch(v) for v in rtr):
            raise ValueError("rtr_allowed_base_commands must be single lowercase command words")
        vendors = frozenset(str(v).strip().lower() for v in raw.get("enabled_vendors", defaults.enabled_vendors))
        if not vendors:
            raise ValueError("enabled_vendors must not be empty")
        return cls(
            agent_contain_host=mode,
            escalate_actions=actions("escalate_actions"),
            agent_auto_allow_actions=actions("agent_auto_allow_actions"),
            agent_denied_actions=actions("agent_denied_actions"),
            rtr_allowed_base_commands=rtr,
            two_person_actions=actions("two_person_actions"),
            approval_ttl_seconds=ttl,
            enabled_vendors=vendors,
            policy_version=str(raw.get("policy_version", defaults.policy_version)),
        )

    def as_dict(self) -> dict[str, Any]:
        out = asdict(self)
        return {k: sorted(v) if isinstance(v, frozenset) else v for k, v in out.items()}


@dataclass(frozen=True)
class VerifiedDetection:
    """A detection the server fetched from the EDR. Never constructed from caller input."""

    vendor: str
    detection_id: str
    host_id: str
    severity: str  # normalized: informational | low | medium | high | critical


@dataclass(frozen=True)
class ResponseDecision:
    action: Decision
    rule_id: str
    reason: str
    intent_hash: str
    intent: dict[str, Any]
    policy_version: str
    required_approvals: int = 0
    approval_ttl_seconds: int = 0
    verified_severity: str | None = None
    execution: str = "not_executed"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_response_intent(
    intent: ResponseIntent,
    policy: ResponsePolicy,
    *,
    verified_detection: VerifiedDetection | None = None,
) -> ResponseDecision:
    """Deterministically decide a response intent. First matching rule wins."""
    intent_hash = intent.intent_hash()
    severity = None
    if verified_detection is not None:
        if (
            verified_detection.vendor != intent.vendor
            or verified_detection.detection_id != intent.detection_id
            or verified_detection.host_id != intent.host_id
        ):
            raise ValueError("verified_detection does not match the intent's vendor, detection, and host")
        severity = verified_detection.severity

    def decide(action: Decision, rule_id: str, reason: str) -> ResponseDecision:
        approvals = 0
        if action == "escalate":
            approvals = 2 if intent.action in policy.two_person_actions else 1
        return ResponseDecision(
            action=action,
            rule_id=rule_id,
            reason=reason,
            intent_hash=intent_hash,
            intent=intent.canonical(),
            policy_version=policy.policy_version,
            required_approvals=approvals,
            approval_ttl_seconds=policy.approval_ttl_seconds,
            verified_severity=severity,
        )

    is_agent = intent.actor_type == "agent"
    if intent.vendor not in policy.enabled_vendors:
        return decide("deny", "vendor-not-enabled", f"vendor {intent.vendor!r} is not enabled for this tenant")
    if is_agent and intent.action in policy.agent_denied_actions:
        return decide("deny", "agent-action-denied", f"agents may not request {intent.action}")
    if intent.action == "rtr_command" and intent.params["base_command"] not in policy.rtr_allowed_base_commands:
        return decide("deny", "rtr-command-not-allowed", "RTR base command is not allowlisted")
    if is_agent and intent.action == "contain_host":
        mode = policy.agent_contain_host
        if mode == "deny":
            return decide("deny", "agent-contain-host-denied", "tenant setting denies agent-initiated containment")
        if mode == "auto_allow_critical" and severity == "critical":
            return decide("allow", "agent-contain-host-critical", "server-verified critical detection on this host")
        return decide("escalate", "agent-contain-host-escalate", "agent-initiated containment requires approval")
    if intent.action in policy.escalate_actions:
        return decide("escalate", "action-requires-approval", f"{intent.action} requires operator approval")
    if is_agent and intent.action not in policy.agent_auto_allow_actions:
        return decide("escalate", "agent-default-escalate", "agent actions require approval unless auto-allowed")
    return decide("allow", "response-policy-allow", "intent satisfies response policy")


__all__ = [
    "ACTOR_TYPES",
    "AGENT_CONTAIN_HOST_MODES",
    "RESPONSE_ACTIONS",
    "ResponseDecision",
    "ResponseIntent",
    "ResponsePolicy",
    "VerifiedDetection",
    "evaluate_response_intent",
]
