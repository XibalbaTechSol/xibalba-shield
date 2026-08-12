"""
Event router — the coordination piece of Agent Core (spec §4.2): subscribes to a sensor's
event stream, routes each event through the Policy Engine, immediately acts on a `contain`
decision via the Action Broker (real OS-level process freeze — this is the "antivirus-speed"
enforcement step, and it runs before anything else in handle() so it's never delayed by a
network call), and — for AgentEvent instances specifically — additionally through the
Guardrail Hooks, before emitting an OpenTelemetry span and (when an exporter is configured)
handing the resulting PolicyDecision to the Integrity Exporter for a real signed BCC commitment.

This module owns NO policy logic itself (that's policy_engine's job) and makes no enforcement
decisions of its own — it only carries out an already-made decision (contain via Action Broker,
export via OTel/Integrity Exporter) — kept deliberately dumb so a routing bug can never also
become a false-enforcement bug.

Two speed classes, deliberately kept separate: containment (Action Broker) is local, in-process,
OS-signal-based, and effectively instant — it runs first, unconditionally, before any network
call. Evidence export (OTel span, Integrity Exporter) is comparatively slow (a real BCC
submission measured at 200-700ms against a live bcc_middleware) and runs after containment,
so evidence-export latency can never delay the actual protective action. The OTel span and the
Integrity Exporter are themselves two independent, separately best-effort export paths —
restored 2026-08-12 after a 2026-08-07 refactor replaced the exporter with OTel-only telemetry
and left Shield with no path to a signed commitment (see xibalba-shield/IMPLEMENTATION_PLAN.md's
former "Known gap — 2026-08-12"). They run in separate try/except blocks deliberately: a
slow/unreachable bcc_middleware failing the exporter call must never suppress the OTel span, and
a tracer/exporter-shim bug must never suppress the signed commitment attempt.
"""

from __future__ import annotations

import json
import logging
from typing import Callable, Iterable, Protocol

from integrity_sdk.telemetry.tracing import get_tracer

from ..schemas.events import AgentEvent, ExportStatus, NormalizedEvent, PolicyDecision
from ..policy_engine.engine import EvaluationContext, PolicyEngine
from .action_broker import ActionBroker
from .eventlog import EventLog
from .registry import AgentRegistry, DeviceContext

logger = logging.getLogger("shield.agent_core.router")
tracer = get_tracer("xibalba-shield")


class ExporterLike(Protocol):
    def export_event(self, event: NormalizedEvent) -> None: ...
    def export_decision(self, decision: PolicyDecision) -> dict: ...


def _pid_of(event: NormalizedEvent) -> int | None:
    """Best-effort extraction of the OS pid a `contain` decision should act on. Only
    ProcessActivity/FileActivity/NetworkFlow carry a `process.pid` (AgentEvent doesn't --
    it has no OS process of its own, and its `contain`/`escalate` actions are meant to be
    handled by the guardrail hooks that wrap an agent's own tool calls, not by Action Broker)."""
    process = getattr(event, "process", None)
    return getattr(process, "pid", None)


class EventRouter:
    def __init__(
        self,
        *,
        device: DeviceContext,
        registry: AgentRegistry,
        policy_engine: PolicyEngine,
        exporter: ExporterLike | None = None,
        action_broker: ActionBroker | None = None,
        guardrail_hooks: Iterable[Callable[[AgentEvent, PolicyDecision], None]] = (),
        event_log: EventLog | None = None,
    ) -> None:
        self.device = device
        self.registry = registry
        self.policy_engine = policy_engine
        self.exporter = exporter
        self.action_broker = action_broker
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

        # Real-time containment first, before anything else -- this is the antivirus-speed
        # step. Freeze-only (no timeout_seconds): ActionBroker.contain() with a timeout BLOCKS
        # the caller until it elapses before escalating to SIGKILL, which would stall this
        # entire loop for however long that timeout is -- exactly the kind of delay a
        # real-time enforcement path must never have. If timed escalation-to-kill is wanted
        # later, it needs its own background timer, not an inline call here.
        if self.action_broker is not None and decision.decision.action == "contain":
            pid = _pid_of(event)
            if pid is not None:
                try:
                    result = self.action_broker.contain(pid)
                    logger.warning(
                        "contained pid %s for decision on %s: %s (%s)",
                        pid, decision.event_ref.event_id, result.action, result.method,
                    )
                except Exception:  # noqa: BLE001
                    # A failed containment attempt must never take down the router or block
                    # export/logging of the decision that was already made -- it's logged
                    # loudly (not silently swallowed) so a broken broker doesn't read as a
                    # quiet no-op.
                    logger.exception(
                        "containment failed for pid %s on decision %s", pid, decision.event_ref.event_id
                    )
            else:
                logger.warning(
                    "decision %s is 'contain' but event carries no pid to act on (class=%s)",
                    decision.event_ref.event_id, decision.event_ref.klass,
                )

        if isinstance(event, AgentEvent):
            for hook in self.guardrail_hooks:
                try:
                    hook(event, decision)
                except Exception:  # noqa: BLE001
                    # A guardrail hook must never take down the router — matches
                    # pretool_gate.py's own "a gate bug must not brick the session" rule
                    # in the parent repo.
                    logger.exception("guardrail hook raised; continuing")

        # Two independent, separately best-effort export paths (see module docstring): the
        # OTel span always fires; the Integrity Exporter (real signed BCC commitment) only
        # fires when one is configured. Neither may suppress the other's outcome — results
        # are accumulated and merged into a single ExportStatus at the end rather than each
        # path overwriting decision.export wholesale.
        export_attempted = False
        event_exported = False
        decision_exported = False
        authorized: bool | None = None
        reasons: list[str] = []

        try:
            with tracer.start_as_current_span("shield.handle_event") as span:
                span.set_attribute("event.id", decision.event_ref.event_id)
                span.set_attribute("event.class", decision.event_ref.klass)
                span.set_attribute("decision.action", decision.decision.action)

                span.set_attribute("event.payload", json.dumps(event.to_dict()))
                span.set_attribute("decision.payload", json.dumps(decision.to_dict()))

                export_attempted = True
                event_exported = True
        except Exception:  # noqa: BLE001
            logger.exception("telemetry export failed for decision on %s", decision.event_ref.event_id)
            export_attempted = True
            reasons.append("telemetry export raised")

        if self.exporter is not None:
            try:
                self.exporter.export_event(event)
                result = self.exporter.export_decision(decision)
                export_attempted = True
                authorized = result.get("authorized") if isinstance(result, dict) else None
                decision_exported = authorized is True
                if not decision_exported:
                    reasons.append(str(result.get("reason", "")) if isinstance(result, dict) else "")
            except Exception:  # noqa: BLE001
                # Evidence export failing must never roll back an already-made enforcement
                # decision — the decision already happened; export is downstream and
                # best-effort, same posture as bcc_middleware's own Merkle-anchor step in the
                # parent repo.
                logger.exception("integrity export failed for decision on %s", decision.event_ref.event_id)
                export_attempted = True
                reasons.append("integrity export raised")

        decision.export = ExportStatus(
            attempted=export_attempted,
            event_exported=event_exported,
            decision_exported=decision_exported,
            authorized=authorized,
            reason="; ".join(r for r in reasons if r),
        )

        if self.event_log is not None:
            self.event_log.append(decision)

        return decision
