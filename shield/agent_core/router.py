"""
Event router — the coordination piece of Agent Core (spec §4.2): subscribes to a sensor's
event stream, routes each event through the Policy Engine, and — for AgentEvent instances
specifically — additionally through the Guardrail Hooks, before handing the resulting
PolicyDecision (and, where the caller wants raw telemetry too, the event itself) to the
Integrity Exporter.

This module owns NO policy logic itself (that's policy_engine's job) and makes no enforcement
decisions of its own — it is pure plumbing, kept deliberately dumb so a routing bug can never
also become a false-enforcement bug.
"""

from __future__ import annotations

import logging
from typing import Callable, Iterable, Protocol

from ..schemas.events import AgentEvent, ExportStatus, NormalizedEvent, PolicyDecision
from ..policy_engine.engine import EvaluationContext, PolicyEngine
from .eventlog import EventLog
from .registry import AgentRegistry, DeviceContext

logger = logging.getLogger("shield.agent_core.router")


class ExporterLike(Protocol):
    def export_event(self, event: NormalizedEvent) -> None: ...
    def export_decision(self, decision: PolicyDecision) -> dict: ...


class EventRouter:
    def __init__(
        self,
        *,
        device: DeviceContext,
        registry: AgentRegistry,
        policy_engine: PolicyEngine,
        exporter: ExporterLike,
        guardrail_hooks: Iterable[Callable[[AgentEvent, PolicyDecision], None]] = (),
        event_log: EventLog | None = None,
    ) -> None:
        self.device = device
        self.registry = registry
        self.policy_engine = policy_engine
        self.exporter = exporter
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
        outcome synchronously rather than only observing it via the exporter's side effect."""
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
            self.exporter.export_event(event)
            result = self.exporter.export_decision(decision)
            authorized = result.get("authorized") if isinstance(result, dict) else None
            decision.export = ExportStatus(
                attempted=True,
                event_exported=True,
                decision_exported=authorized is True,
                authorized=authorized if isinstance(authorized, bool) else None,
                reason=str(result.get("reason", "")) if isinstance(result, dict) else "",
            )
        except Exception:  # noqa: BLE001
            # Evidence export failing must never roll back an already-made enforcement
            # decision — the decision already happened; export is downstream and best-effort,
            # same posture as bcc_middleware's own Merkle-anchor step in the parent repo.
            logger.exception("integrity export failed for decision on %s", decision.event_ref.event_id)
            decision.export = ExportStatus(attempted=True, reason="integrity export raised")

        if self.event_log is not None:
            self.event_log.append(decision)

        return decision
