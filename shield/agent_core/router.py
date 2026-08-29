"""
Event router — the coordination piece of Agent Core (spec §4.2): subscribes to a sensor's
event stream, routes each event through the Policy Engine (Tier 1), optionally re-evaluates
`escalate` decisions through a Tier-2 SLM backend (`slm_backend.py` — off by default, see
`--slm-backend` in cli.py), immediately acts on a `contain` decision via the Action Broker (real OS-level process freeze — this is the "antivirus-speed"
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
and left Shield with no path to a signed commitment (see
xibalba-shield/docs/archive/2026-08/IMPLEMENTATION_PLAN.md's
former "Known gap — 2026-08-12"). They run in separate try/except blocks deliberately: a
slow/unreachable bcc_middleware failing the exporter call must never suppress the OTel span, and
a tracer/exporter-shim bug must never suppress the signed commitment attempt.
"""

from __future__ import annotations

import json
import logging
from typing import Callable, Iterable, Protocol

from integrity_sdk.telemetry.tracing import get_tracer

from ..schemas.events import AgentEvent, EnforcementOutcome, ExportStatus, NormalizedEvent, PolicyDecision
from ..policy_engine.engine import EvaluationContext, PolicyEngine
from .action_broker import ActionBroker
from .eventlog import EventLog
from .registry import AgentRegistry, DeviceContext
from .slm_backend import SlmBackend

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
        slm_backend: SlmBackend | None = None,
        enforcement_outcome_sink: Callable[[EnforcementOutcome], None] | None = None,
    ) -> None:
        self.device = device
        self.registry = registry
        self.policy_engine = policy_engine
        self.exporter = exporter
        self.action_broker = action_broker
        self.guardrail_hooks = list(guardrail_hooks)
        self.event_log = event_log
        self.slm_backend = slm_backend
        # Optional, injectable, same pattern as `event_log`/`exporter` -- keeps this module's
        # "no policy logic, no persistence of its own" stance (see module docstring) even
        # though it now reports enforcement outcomes. A caller supplies where they go (e.g.
        # shield/backend/store.py's enforcement_outcomes table); router.py never persists
        # anything itself.
        self.enforcement_outcome_sink = enforcement_outcome_sink

    def _context(self) -> EvaluationContext:
        return EvaluationContext(
            tenant_id=self.device.tenant_id,
            device_role=self.device.device_role,
            device_id=self.device.device_id,
            registered_agent_ids=self.registry.registered_ids(),
        )

    def _report_enforcement_outcome(self, outcome: EnforcementOutcome) -> None:
        """Best-effort only -- a sink failure (e.g. the backend store is down) must never
        propagate out of handle() any more than a containment failure itself does. This is
        its own separate try/except, deliberately not nested inside the containment
        try/except above, so a persistence bug can never be mistaken for a containment bug
        in the logs."""
        if self.enforcement_outcome_sink is None:
            return
        try:
            self.enforcement_outcome_sink(outcome)
        except Exception:  # noqa: BLE001
            logger.exception("failed to persist enforcement outcome for %s", outcome.event_id)

    def handle(self, event: NormalizedEvent) -> PolicyDecision:
        """Process one normalized event end-to-end. Returns the PolicyDecision so callers
        (tests, the dev-mode sensor loop, guardrail hook call sites) can inspect the
        outcome synchronously."""
        if isinstance(event, AgentEvent):
            self.registry.touch(event.agent.agent_id)

        decision = self.policy_engine.evaluate(event, self._context())

        # Tier-2 escalation: only for events Tier 1 (the deterministic PolicyEngine) already
        # flagged `escalate` -- an SLM backend is never the first evaluator an event sees, and
        # `slm_backend=None` (the default) makes this block a no-op, so existing behavior is
        # unchanged unless an operator explicitly opts in via `shield run --slm-backend ...`.
        # A revised `contain` from Tier 2 still flows through the real ActionBroker below, same
        # as a Tier-1 `contain` would -- the SLM never contains a process itself.
        if self.slm_backend is not None and decision.decision.action == "escalate":
            try:
                tier1_decision = decision
                decision = self.slm_backend.evaluate(event, self._context())
                decision.decision.tier = "tier2" if decision.decision.action != "escalate" else "tier2_unresolved"
                logger.info(
                    "Tier-2 SLM revised decision for %s: tier1=%s -> tier2=%s (%s)",
                    tier1_decision.event_ref.event_id, tier1_decision.decision.action,
                    decision.decision.action, decision.rule.rule_id,
                )
            except Exception:  # noqa: BLE001
                # A broken/unavailable Tier-2 backend must never take down the router or
                # silently mask the Tier-1 decision -- fall back to what Tier 1 already decided.
                logger.exception(
                    "Tier-2 SLM backend raised; keeping Tier-1 decision %s", decision.event_ref.event_id
                )

        # A2A escalation fallback (docs/archive/2026-08/2026-08-18-a2a-escalation-schema-proposal.md):
        # if the decision is STILL `escalate` at this point -- either no Tier 2 was configured
        # at all, or Tier 2 was consulted and remained genuinely uncertain -- there is no Tier 3
        # to hand off to (none exists yet, deliberately deferred). Before this fallback existed,
        # an unresolved `escalate` flowed straight through to containment-check (which only acts
        # on `action == "contain"`, so it never fired) and out to export/logging exactly as any
        # other decision would -- a real, silent no-decision outcome. Fail-closed, matching this
        # repo's inherited posture from bcc_middleware ("any failure to positively confirm
        # 'allowed' denies the request") and this router's own real-time enforcement stance:
        # irreducible uncertainty about a potentially dangerous action is treated as dangerous,
        # not waved through. `tier` is left as whichever tier actually produced the `escalate`
        # verdict (tier1 if Tier 2 was never consulted, tier2 if it was and remained uncertain)
        # -- this rewrites the ACTION, not the provenance of who asked for escalation.
        if decision.decision.action == "escalate":
            original_reason = decision.decision.reason
            decision.decision.action = "contain"
            decision.decision.reason = (
                f"A2A_UNRESOLVED_ESCALATION: no Tier 3 configured, failing closed to contain "
                f"(original: {original_reason})"
            )
            logger.warning(
                "unresolved escalation for %s (tier=%s) -- no Tier 3 configured, "
                "falling back to contain (fail-closed)",
                decision.event_ref.event_id, decision.decision.tier,
            )

        # Real-time containment first, before anything else -- this is the antivirus-speed
        # step. Freeze-only (no timeout_seconds): ActionBroker.contain() with a timeout BLOCKS
        # the caller until it elapses before escalating to SIGKILL, which would stall this
        # entire loop for however long that timeout is -- exactly the kind of delay a
        # real-time enforcement path must never have. If timed escalation-to-kill is wanted
        # later, it needs its own background timer, not an inline call here.
        if self.action_broker is not None and decision.decision.action == "contain":
            pid = _pid_of(event)
            agent_id = event.agent.agent_id if isinstance(event, AgentEvent) else None
            if pid is not None:
                try:
                    result = self.action_broker.contain(pid)
                    logger.warning(
                        "contained pid %s for decision on %s: %s (%s)",
                        pid, decision.event_ref.event_id, result.action, result.method,
                    )
                    if self.enforcement_outcome_sink is not None:
                        # getattr-defensive, not result.completed directly: ActionBroker's
                        # real return type (ActionResult) always has these fields, but a
                        # caller-supplied broker (tests, alternate implementations) may
                        # return a narrower duck-typed object -- this must never turn a
                        # genuinely successful containment into a misreported failure just
                        # because persistence-shape introspection failed.
                        self._report_enforcement_outcome(
                            EnforcementOutcome(
                                event_id=decision.event_ref.event_id, device_id=self.device.device_id,
                                action=getattr(result, "action", "contain"),
                                completed=getattr(result, "completed", True),
                                escalated=getattr(result, "escalated", False),
                                error=getattr(result, "error", None), agent_id=agent_id,
                            )
                        )
                except Exception as exc:  # noqa: BLE001
                    # A failed containment attempt must never take down the router or block
                    # export/logging of the decision that was already made -- it's logged
                    # loudly (not silently swallowed) so a broken broker doesn't read as a
                    # quiet no-op. Persisting the failure outcome shares the exact same
                    # guarantee -- see _report_enforcement_outcome.
                    logger.exception(
                        "containment failed for pid %s on decision %s", pid, decision.event_ref.event_id
                    )
                    self._report_enforcement_outcome(
                        EnforcementOutcome(
                            event_id=decision.event_ref.event_id, device_id=self.device.device_id,
                            action="contain", completed=False, error=str(exc), agent_id=agent_id,
                        )
                    )
            else:
                logger.warning(
                    "decision %s is 'contain' but event carries no pid to act on (class=%s)",
                    decision.event_ref.event_id, decision.event_ref.klass,
                )
                self._report_enforcement_outcome(
                    EnforcementOutcome(
                        event_id=decision.event_ref.event_id, device_id=self.device.device_id,
                        action="contain", completed=False, error="no pid to act on", agent_id=agent_id,
                    )
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
        verification_token: str | None = None
        batch_index: int | None = None
        agent_id: str | None = None
        nonce: int | None = None
        intended_state_hash: str | None = None
        invocation_id: str | None = decision.invocation_id
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
                verification_token = result.get("verification_token") if isinstance(result, dict) else None
                batch_index = result.get("batch_index") if isinstance(result, dict) else None
                agent_id = result.get("agent_id") if isinstance(result, dict) else None
                nonce = result.get("nonce") if isinstance(result, dict) else None
                intended_state_hash = result.get("intended_state_hash") if isinstance(result, dict) else None
                invocation_id = (result.get("invocation_id") or decision.invocation_id) if isinstance(result, dict) else decision.invocation_id
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
            verification_token=verification_token,
            batch_index=batch_index,
            agent_id=agent_id,
            nonce=nonce,
            intended_state_hash=intended_state_hash,
            invocation_id=invocation_id,
        )

        if self.event_log is not None:
            self.event_log.append(decision)

        return decision
