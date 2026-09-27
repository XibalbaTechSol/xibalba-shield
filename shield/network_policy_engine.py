"""Deterministic first-line network policy evaluation.

The evaluator returns a decision only. Authorization and adapter execution remain separate
boundaries in ``network_policy`` and ``network_adapters``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class NetworkRule:
    rule_id: str
    action: str
    reason_code: str
    match: Mapping[str, Any]
    require_approval: bool = False


@dataclass(frozen=True)
class NetworkPolicyDecision:
    action: str
    rule_id: str
    reason_code: str
    policy_version: str
    policy_hash: str
    human_review_required: bool


class NetworkPolicyEngine:
    """First-match deterministic evaluator over bounded, structured network facts."""

    def __init__(self, rules: list[NetworkRule], *, version: str = "1.0.0") -> None:
        self.rules = tuple(rules)
        self.version = version
        canonical = [{"rule_id": r.rule_id, "action": r.action, "reason_code": r.reason_code, "match": dict(r.match), "require_approval": r.require_approval} for r in self.rules]
        digest = hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.policy_hash = "sha256:" + digest

    @classmethod
    def from_dicts(cls, rules: list[Mapping[str, Any]], *, version: str = "1.0.0") -> "NetworkPolicyEngine":
        return cls([NetworkRule(str(item["rule_id"]), str(item["action"]), str(item.get("reason_code") or "RULE_MATCH"), dict(item.get("match") or {}), bool(item.get("require_approval", False))) for item in rules], version=version)

    @staticmethod
    def _value(observed: Mapping[str, Any], path: str) -> Any:
        value: Any = observed
        for part in path.split("."):
            if not isinstance(value, Mapping):
                return None
            value = value.get(part)
        return value

    @classmethod
    def _matches(cls, observed: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
        for path, wanted in expected.items():
            actual = cls._value(observed, path)
            choices = wanted if isinstance(wanted, list) else [wanted]
            if actual not in choices:
                return False
        return True

    def evaluate(self, observed: Mapping[str, Any]) -> NetworkPolicyDecision:
        for rule in self.rules:
            if self._matches(observed, rule.match):
                return NetworkPolicyDecision(rule.action, rule.rule_id, rule.reason_code, self.version, self.policy_hash, rule.require_approval)
        return NetworkPolicyDecision("log_only", "_network_no_match", "NO_MATCH", self.version, self.policy_hash, False)


__all__ = ["NetworkPolicyDecision", "NetworkPolicyEngine", "NetworkRule"]
