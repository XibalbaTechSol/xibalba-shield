"""
Policy Engine — spec/xibalba-shield-v1.md §4.3.

Evaluates normalized events (schemas/events.py) against table-driven rules (schemas/
policy_rule.py) in rule-priority (list) order, first match wins. Every evaluation produces a
PolicyDecision — matched or not, allowed or denied — mirroring bcc_middleware's own posture in
the parent repo (docs/INTERFACE_CONTRACT.md §7's "no assume-success fallback"): `log_only` and
`allow` are as visible in the audit trail as a `deny`.

MUST be able to enforce with zero cloud round-trip (§4.3) — this module makes no network calls
and never will; that's the Integrity Exporter's job, downstream of a decision already made.
"""

from __future__ import annotations

import fnmatch
import uuid
from dataclasses import dataclass

from ..schemas.events import (
    Decision,
    EventRef,
    NormalizedEvent,
    PolicyRef,
    PolicyDecision,
    RuleRef,
)
from ..schemas.policy_rule import Condition, PolicyRule


def _field_matches(actual: object, allowed: list[object]) -> bool:
    """One `match` field: ANY of `allowed` matching `actual` satisfies it. Strings support
    glob patterns (`*/ai/*.exe`, per spec §7's example); everything else is exact equality.

    When `actual` is itself a list (`AgentContext.data_sources`/`.tools_called` are the only
    such fields today), ANY element of it matching ANY of `allowed` satisfies the field — a
    rule naming `data_sources: ["ehr_encounter"]` must match an event whose `data_sources` is
    `["ehr_encounter", "billing_db"]`, not require the whole list to equal one exact value."""
    if isinstance(actual, list):
        return any(_field_matches(item, allowed) for item in actual)
    for candidate in allowed:
        if isinstance(candidate, str) and isinstance(actual, str):
            if fnmatch.fnmatch(actual, candidate):
                return True
        elif actual == candidate:
            return True
    return False


def _event_severity(event: NormalizedEvent) -> str:
    """`Activity.severity` (Process/File/NetworkFlow) and `AgentActivity.risk_level`
    (AgentEvent) name the same concept under different field names — spec §5.1-5.4's own
    shapes, not a naming inconsistency this engine introduced. Reading both explicitly here
    keeps every event class's evaluate() path uniform without renaming either canonical field."""
    activity = getattr(event, "activity", None)
    if activity is None:
        return "low"
    return getattr(activity, "severity", None) or getattr(activity, "risk_level", None) or "low"


def _event_field_group(event: NormalizedEvent, group: str) -> dict | None:
    """Pull the named field group (`process`, `agent`, `file`, `flow`, `context`) off a
    normalized event as a plain dict, or None if this event class doesn't carry that group —
    a condition naming a group the event doesn't have simply doesn't match, it doesn't error.

    `context` and `activity` were added alongside the four non-tool_execution guardrail hooks
    (ingress, retrieval/context, model routing, output, post-action verification — spec §4.4):
    those hooks carry their most policy-relevant data on `AgentEvent.context`
    (`model_endpoint`, `data_sources`) and `.activity` (`risk_level` — the whole point of the
    output hook), not `.agent`. Without both, a rule could gate on which agent made a call but
    never on which model it routed to, which data source it touched, or how risky its output
    was classified — exactly the fields those hook points exist to police."""
    attr_map = {
        "process": "process", "agent": "agent", "file": "file", "flow": "flow",
        "context": "context", "activity": "activity",
    }
    attr = attr_map.get(group)
    if attr is None or not hasattr(event, attr):
        return None
    value = getattr(event, attr)
    return vars(value) if value is not None else None


def _condition_matches(condition: Condition, event: NormalizedEvent, registered_agent_ids: set[str]) -> bool:
    if condition.type == "agent":
        # `registered` is a synthetic field the engine derives from the caller-supplied
        # registry, not a literal attribute on AgentInfo — this is the shadow-AI-discovery
        # check spec §4.2 describes ("an agent with no registry entry is unregistered").
        registered_wanted = condition.match.get("registered")
        if registered_wanted is not None:
            agent = getattr(event, "agent", None)
            if agent is None:
                return False
            is_registered = bool(agent) and agent.agent_id in registered_agent_ids
            if bool(registered_wanted[0]) != is_registered:
                return False
        remaining = {k: v for k, v in condition.match.items() if k != "registered"}
        group = _event_field_group(event, "agent") or {}
        for field_name, allowed in remaining.items():
            if not _field_matches(group.get(field_name), allowed):
                return False
        return True

    group = _event_field_group(event, condition.type)
    if group is None:
        return False
    for field_name, allowed in condition.match.items():
        if not _field_matches(group.get(field_name), allowed):
            return False
    return True


@dataclass
class EvaluationContext:
    """Per-evaluation scope inputs the engine needs beyond the event itself."""

    tenant_id: str = ""
    device_role: str = ""
    device_id: str = ""
    registered_agent_ids: frozenset[str] = frozenset()


class PolicyEngine:
    """Stateless over a fixed, ordered rule set — callers own reloading rules (§4.6's
    config/update module is what re-instantiates this with a new rule list, not this class
    itself watching a file)."""

    def __init__(self, rules: list[PolicyRule], *, policy_version: str = "", policy_hash: str = ""):
        self.rules = rules
        self.policy_version = policy_version
        self.policy_hash = policy_hash

    def evaluate(self, event: NormalizedEvent, ctx: EvaluationContext) -> PolicyDecision:
        event_id = f"evt-{uuid.uuid4().hex[:12]}"
        for rule in self.rules:
            if not rule.scope.matches(ctx.tenant_id, ctx.device_role):
                continue
            if not rule.conditions:
                continue
            if all(_condition_matches(c, event, set(ctx.registered_agent_ids)) for c in rule.conditions):
                action = rule.actions[0] if rule.actions else None
                return PolicyDecision(
                    device_id=ctx.device_id,
                    event_ref=EventRef(klass=event.klass, event_id=event_id),
                    rule=RuleRef(rule_id=rule.rule_id, name=rule.name, version=rule.version),
                    policy=PolicyRef(version=self.policy_version, hash=self.policy_hash),
                    decision=Decision(
                        action=action.type if action else "log_only",
                        reason=action.message if action else "matched with no action defined",
                        severity=_event_severity(event),
                    ),
                )

        # No rule matched — this IS still a real PolicyDecision, not a silent no-op, per this
        # module's own docstring: allow/log_only must be as visible in the audit trail as deny.
        return PolicyDecision(
            device_id=ctx.device_id,
            event_ref=EventRef(klass=event.klass, event_id=event_id),
            rule=RuleRef(rule_id="_no_match", name="No rule matched", version="0"),
            policy=PolicyRef(version=self.policy_version, hash=self.policy_hash),
            decision=Decision(action="allow", reason="no policy rule matched", severity="low"),
        )
