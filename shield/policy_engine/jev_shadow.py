"""Jev shadow analysis for Shield.

This module is deliberately downstream of deterministic policy evaluation. It emits an
observational DecisionTrace projection and never mutates the PolicyDecision, invokes a responder,
signs a receipt, or changes enforcement mode.

Failure vocabulary
------------------
A provider can be down, slow, mis-keyed, return garbage, or answer about the wrong event. All of
those leave enforcement untouched (proven differentially in tests/test_jev_failure_modes.py), but
"unavailable" alone does not tell an operator which one happened. Every failed advisory therefore
carries a stable `reason_code`, in the log line and in the stored advisory row:

==================================  ==========  =============================================
reason_code                         status      meaning
==================================  ==========  =============================================
ADVISORY_PROVIDER_TIMEOUT           unavailable no answer within the configured timeout
ADVISORY_PROVIDER_UNREACHABLE       unavailable connection refused, DNS failure, network down
ADVISORY_PROVIDER_HTTP_ERROR        unavailable server answered with an HTTP error (401, 500...)
ADVISORY_PROVIDER_MALFORMED_RESPONSE unavailable not JSON, wrong shape, or an ill-typed field
ADVISORY_PROVIDER_OUTPUT_REJECTED   unavailable well-formed but refused by DecisionTrace's own
                                    validation (probability outside 0..1, too many entries)
ADVISORY_PROVIDER_ERROR             unavailable anything else the provider raised
ADVISORY_OBSERVED_HASH_MISMATCH     rejected    advice about a *different* event than the one
                                    analyzed
==================================  ==========  =============================================

Only the exception's *type* is classified and logged. Neither its message nor any response body is,
because provider-returned content must not reach a log line (docs/EXECUTION_PLAN.md B5).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import json
import logging
import socket
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError

from integrity_sdk.core.decision_trace import (
    DecisionEnvelope,
    DecisionTraceError,
    FixtureJevProvider,
    GENESIS_PARENT,
    JevAnalysis,
    JevProvider,
)

from ..schemas.events import NormalizedEvent, PolicyDecision

logger = logging.getLogger(__name__)

ADVISORY_PROVIDER_TIMEOUT = "ADVISORY_PROVIDER_TIMEOUT"
ADVISORY_PROVIDER_UNREACHABLE = "ADVISORY_PROVIDER_UNREACHABLE"
ADVISORY_PROVIDER_HTTP_ERROR = "ADVISORY_PROVIDER_HTTP_ERROR"
ADVISORY_PROVIDER_MALFORMED_RESPONSE = "ADVISORY_PROVIDER_MALFORMED_RESPONSE"
ADVISORY_PROVIDER_OUTPUT_REJECTED = "ADVISORY_PROVIDER_OUTPUT_REJECTED"
ADVISORY_PROVIDER_ERROR = "ADVISORY_PROVIDER_ERROR"
ADVISORY_OBSERVED_HASH_MISMATCH = "ADVISORY_OBSERVED_HASH_MISMATCH"


@dataclass(frozen=True)
class ShieldJevAnalysis(JevAnalysis):
    """A `JevAnalysis` that can say *why* it is not an available advisory.

    `JevAnalysis` has no reason field, and it belongs to integrity-core's SDK, so this is a
    Shield-local subclass rather than a cross-package schema change. Healthy advisories stay
    plain `JevAnalysis` objects; consumers read this with `getattr(analysis, "reason_code", None)`.
    """

    reason_code: str | None = None


def _cause_chain(exc: BaseException, limit: int = 6) -> list[BaseException]:
    """`exc` and its explicit `__cause__` chain. `HttpInferenceProvider` wraps transport
    failures as `RuntimeError(...) from exc`, so the interesting type is one level down.
    Implicit `__context__` is deliberately ignored: it can name an unrelated earlier error."""
    chain: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and len(chain) < limit and current not in chain:
        chain.append(current)
        current = current.__cause__
    return chain


def classify_provider_failure(exc: BaseException) -> str:
    """Map whatever a provider raised onto one stable reason code. Never raises."""
    chain = _cause_chain(exc)
    # Order matters: DecisionTraceError, HTTPError and TimeoutError are all subclasses of types
    # tested later (ValueError, URLError/OSError), so the specific cases must be tried first.
    if any(isinstance(e, DecisionTraceError) for e in chain):
        return ADVISORY_PROVIDER_OUTPUT_REJECTED
    if any(isinstance(e, HTTPError) for e in chain):
        return ADVISORY_PROVIDER_HTTP_ERROR
    for e in chain:
        if isinstance(e, (TimeoutError, socket.timeout)):
            return ADVISORY_PROVIDER_TIMEOUT
        if isinstance(e, URLError) and isinstance(e.reason, (TimeoutError, socket.timeout)):
            return ADVISORY_PROVIDER_TIMEOUT
    if any(isinstance(e, (URLError, OSError)) for e in chain):
        return ADVISORY_PROVIDER_UNREACHABLE
    if any(isinstance(e, (ValueError, TypeError, KeyError, IndexError, AttributeError)) for e in chain):
        return ADVISORY_PROVIDER_MALFORMED_RESPONSE
    return ADVISORY_PROVIDER_ERROR


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
        provider_id = str(getattr(self.provider, "provider_id", "jev.unknown"))
        try:
            analysis = self.provider.analyze(envelope)
            if not isinstance(analysis, JevAnalysis):
                # A provider that returns the wrong type would otherwise raise below, in the
                # sink, and the advisory record would be lost with nothing operator-readable.
                raise TypeError(f"provider returned {type(analysis).__name__}, not JevAnalysis")
        except Exception as exc:  # noqa: BLE001 -- any provider failure is an unavailable advisory
            code = classify_provider_failure(exc)
            # Type name only. The message may embed response content, which must not be logged.
            logger.warning(
                "jev advisory unavailable: reason=%s provider=%s exception=%s event_id=%s",
                code, provider_id, type(exc).__name__, event_id,
            )
            analysis = ShieldJevAnalysis(provider_id, "unavailable", reason_code=code)
        else:
            if analysis.observed_event_hash not in (None, envelope.event_hash):
                # "Every advisory projection links to the observed event hash." Advice about some
                # other event is not unavailable -- it arrived -- but it is not advice about THIS
                # event either, and recording it as `available` would put a false link in the
                # evidence trail. Only a positive mismatch is rejected; no link at all is not a
                # contradicting one.
                logger.warning(
                    "jev advisory rejected: reason=%s provider=%s event_id=%s",
                    ADVISORY_OBSERVED_HASH_MISMATCH, provider_id, event_id,
                )
                analysis = ShieldJevAnalysis(
                    provider_id, "rejected", reason_code=ADVISORY_OBSERVED_HASH_MISMATCH,
                )
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
                            # None for a healthy advisory. Additive: existing readers ignore it.
                            "reason_code": getattr(analysis, "reason_code", None),
                            "causal_claim": False}, "created_at": envelope.timestamp}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


__all__ = ["JevShadowAnalyzer", "JsonlDecisionTraceSink", "ShieldJevAnalysis", "classify_provider_failure"]
