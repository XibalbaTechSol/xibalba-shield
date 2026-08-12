"""
Event router — the coordination piece of Agent Core (spec §4.2): subscribes to a sensor's
event stream, routes each event through the Policy Engine, and — for AgentEvent instances
specifically — additionally through the Guardrail Hooks. Telemetry is emitted directly
using standard OpenTelemetry spans via the integrity-sdk tracer.

This module owns NO policy logic itself (that's policy_engine's job) and makes no enforcement
decisions of its own — it is pure plumbing, kept deliberately dumb so a routing bug can never
also become a false-enforcement bug.
"""

from __future__ import annotations

import json
import logging
from typing import Callable, Iterable

from integrity_sdk.telemetry.tracing import get_tracer

from ..schemas.events import AgentEvent, ExportStatus, NormalizedEvent, PolicyDecision
from ..policy_engine.engine import EvaluationContext, PolicyEngine
from .eventlog import EventLog
from .registry import AgentRegistry, DeviceContext

logger = logging.getLogger("shield.agent_core.router")
tracer = get_tracer("xibalba-shield")


class EventRouter:
    def __init__(
        self,
        *,
        device: DeviceContext,
        registry: AgentRegistry,
        policy_engine: PolicyEngine,
        guardrail_hooks: Iterable[Callable[[AgentEvent, PolicyDecision], None]] = (),
        event_log: EventLog | None = None,
    ) -> None:
        self.device = device
        self.registry = registry
        self.policy_engine = policy_engine
        self.guardrail_hooks = list(guardrail_hooks)
        self.event_log = event_log

    def _context(self) -> EvaluationContext:
        return EvaluationContext(
            tenant_id=self.device.tenant_id,
            device_role=self.device.device_role,
            device_id=self.device.device_id,
            registered_agent_ids=self.registry.registered_ids(),
        )

    def handle(self, event: NormalizedEvent) -> PolicyDecision:
        """Process one normalized event end-to-end. Returns the PolicyDecision so callers
        (tests, the dev-mode sensor loop, guardrail hook call sites) can inspect the
        outcome synchronously."""
        if isinstance(event, AgentEvent):
            self.registry.touch(event.agent.agent_id)

        decision = self.policy_engine.evaluate(event, self._context())

        if isinstance(event, AgentEvent):
            for hook in self.guardrail_hooks:
                try:
                    hook(event, decision)
                except Exception:  # noqa: BLE001
                    # A guardrail hook must never take down the router — matches
                    # pretool_gate.py's own "a gate bug must not brick the session" rule
                    # in the parent repo.
                    logger.exception("guardrail hook raised; continuing")

        try:
            with tracer.start_as_current_span("shield.handle_event") as span:
                span.set_attribute("event.id", decision.event_ref.event_id)
                span.set_attribute("event.class", decision.event_ref.klass)
                span.set_attribute("decision.action", decision.decision.action)
                
                span.set_attribute("event.payload", json.dumps(event.to_dict()))
                span.set_attribute("decision.payload", json.dumps(decision.to_dict()))

                decision.export = ExportStatus(
                    attempted=True,
                    event_exported=True,
                    decision_exported=True,
                    authorized=True,
                    reason="",
                )
        except Exception:  # noqa: BLE001
            logger.exception("telemetry export failed for decision on %s", decision.event_ref.event_id)
            decision.export = ExportStatus(attempted=True, reason="telemetry export raised")

        if self.event_log is not None:
            self.event_log.append(decision)

        return decision
