"""
Policy rule shape — spec/xibalba-shield-v1.md §7.

JSON, table-driven, evaluated by shield/policy_engine in rule-priority (list) order,
first-match wins. `ais_impact` is a HINT consumed by a future oracle-side mapping layer (spec
§8) — it is never written directly to AIS from here. Shield does not compute AIS; the oracle's
scoring-core remains the sole computer of any score (protocol spec §8.1), and this repo has no
code path that bypasses that.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Action = Literal["allow", "deny", "contain", "log_only", "escalate"]


@dataclass
class RuleScope:
    tenants: list[str] = field(default_factory=list)
    device_roles: list[str] = field(default_factory=list)

    def matches(self, tenant_id: str, device_role: str) -> bool:
        if self.tenants and tenant_id not in self.tenants:
            return False
        if self.device_roles and device_role not in self.device_roles:
            return False
        return True


@dataclass
class Condition:
    """One `conditions[]` entry. `type` names which normalized event field group this
    condition inspects ("process", "agent", "file", "flow", "context", "activity"); `match`
    is a dict of field -> list-of-glob-or-exact-values, ANY of which matching satisfies that
    field. A list-valued field (`context.data_sources`, `context.tools_called`) matches if
    ANY of its elements matches ANY allowed value — see
    `policy_engine.engine._field_matches`."""

    type: str
    match: dict[str, list[Any]]


@dataclass
class RuleAction:
    type: Action
    message: str = ""
    log_decision: bool = True


@dataclass
class AisImpact:
    agent_delta: int = 0
    device_delta: int = 0


@dataclass
class PolicyRule:
    rule_id: str
    name: str
    version: str
    conditions: list[Condition]
    actions: list[RuleAction]
    scope: RuleScope = field(default_factory=RuleScope)
    ais_impact: AisImpact = field(default_factory=AisImpact)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PolicyRule":
        return cls(
            rule_id=d["rule_id"],
            name=d.get("name", d["rule_id"]),
            version=d.get("version", "1.0.0"),
            scope=RuleScope(**d.get("scope", {})),
            conditions=[Condition(**c) for c in d.get("conditions", [])],
            actions=[RuleAction(**a) for a in d.get("actions", [])],
            ais_impact=AisImpact(**d.get("ais_impact", {})),
        )
