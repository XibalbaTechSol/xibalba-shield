"""Jev shadow analysis for Shield.

This module is deliberately downstream of deterministic policy evaluation. It emits an
observational DecisionTrace projection and never mutates the PolicyDecision, invokes a responder,
signs a receipt, or changes enforcement mode.
"""

from __future__ import annotations

from collections.abc import Callable
import json
from pathlib import Path
from typing import Any

from integrity_sdk.core.decision_trace import (
    DecisionEnvelope,
    FixtureJevProvider,
    GENESIS_PARENT,
    JevAnalysis,
    JevProvider,
)

from ..schemas.events import NormalizedEvent, PolicyDecision


class JevShadowAnalyzer:
    """Produce bounded Jev annotations after Shield has already made its decision."""

    def __init__(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        provider: JevProvider | None = None,
        sink: Callable[[DecisionEnvelope, JevAnalysis], None] | None = None,
        parent_resolver: Callable[[str], str | None] | None = None,
        event_classes: tuple[str, ...] = (),
        provider_metadata: dict[str, Any] | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.agent_id = agent_id
        self.provider = provider or FixtureJevProvider()
        self.sink = sink
        self.parent_resolver = parent_resolver
        self.event_classes = frozenset(event_classes)
        self.provider_metadata = dict(provider_metadata or {})
        self._heads: dict[str, str] = {}

    @staticmethod
    def _trace_id(event: NormalizedEvent, decision: PolicyDecision) -> str:
        for name in ("session_id", "trace_id", "turn_id"):
            value = getattr(event, name, None)
            if value:
                return str(value)
        return f"shield:{decision.device_id}"

    def analyze(self, event: NormalizedEvent, decision: PolicyDecision) -> tuple[DecisionEnvelope, JevAnalysis]:
        if self.event_classes and event.klass not in self.event_classes:
            raise LookupError(f"inference event class {event.klass!r} is outside configured scope")
        trace_id = self._trace_id(event, decision)
        parent = (self.parent_resolver(trace_id) if self.parent_resolver is not None else None) or self._heads.get(trace_id, GENESIS_PARENT)
        event_id = decision.event_ref.event_id
        envelope = DecisionEnvelope(
            tenant_id=self.tenant_id,
            agent_id=self.agent_id,
            trace_id=trace_id,
            event_id=event_id,
            event_type="shield.policy_decision",
            timestamp=decision.time,
            invocation_id=decision.invocation_id,
            parent_event_hash=parent,
            policy_ref=decision.policy.hash or decision.policy.version or decision.rule.rule_id,
            policy_decision=decision.decision.action,
            metadata={
                "event_class": decision.event_ref.klass,
                "rule_id": decision.rule.rule_id,
                "severity": decision.decision.severity,
                "risk_hint": decision.decision.severity,
                "decision_tier": decision.decision.tier,
                **self.provider_metadata,
            },
        )
        try:
            analysis = self.provider.analyze(envelope)
        except Exception:
            analysis = JevAnalysis(getattr(self.provider, "provider_id", "jev.unknown"), "unavailable")
        self._heads[trace_id] = envelope.event_hash
        if self.sink is not None:
            self.sink(envelope, analysis)
        return envelope, analysis

    def __call__(self, event: NormalizedEvent, decision: PolicyDecision) -> None:
        self.analyze(event, decision)


class JsonlDecisionTraceSink:
    """Small local handoff from the live router to the authenticated dashboard API."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()

    def __call__(self, envelope: DecisionEnvelope, analysis: JevAnalysis) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        row = {"event_id": envelope.event_id, "trace_id": envelope.trace_id,
               "tenant_id": envelope.tenant_id, "agent_id": envelope.agent_id,
               "session_id": envelope.session_id or envelope.trace_id,
               "sequence_number": 0, "event_hash": envelope.event_hash,
               "parent_event_hash": envelope.parent_event_hash, "envelope": envelope.body(),
               "advisory": {"provider_id": analysis.provider_id, "status": analysis.status,
                            "risk_category": analysis.risk_category,
                            "transition_probabilities": dict(analysis.transition_probabilities),
                            "recommended_escalation": analysis.recommended_escalation,
                            "observed_event_hash": analysis.observed_event_hash,
                            "causal_claim": False}, "created_at": envelope.timestamp}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


__all__ = ["JevShadowAnalyzer", "JsonlDecisionTraceSink"]
