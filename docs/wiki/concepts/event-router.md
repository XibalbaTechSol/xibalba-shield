---
title: Event Router
acronyms: []
created: 2026-08-12
updated: 2026-08-28
type: concept
tags: [enforcement, containment]
confidence: high
source_files:
  - shield/agent_core/router.py
  - shield/agent_core/action_broker.py
  - shield/agent_core/slm_backend.py
---

Every `PolicyDecision` carries a canonical UUID `invocation_id`. For an instrumented
`AgentEvent`, Shield preserves the upstream ID; otherwise it creates a new UUID for the endpoint
action it observed. The ID remains in local decision/export status even if downstream Integrity
export fails. It correlates records but does not itself prove enforcement or effect.

## Table of contents

- [Overview](#overview)
- [Two speed classes, deliberately kept separate](#two-speed-classes-deliberately-kept-separate)
- [guardrailhooks is accepted but not populated by shield run](#guardrailhooks-is-accepted-but-not-populated-by-shield-run)
- [pidof: why AgentEvent never gets contained here](#pidof-why-agentevent-never-gets-contained-here)
- [Restoration note](#restoration-note)
- [Related pages](#related-pages)

## Overview

`EventRouter.handle()` (`shield/agent_core/router.py`) is the single place that turns one
normalized event into a completed, logged decision. It owns no policy logic itself — that is
[Policy Engine](policy-engine.md)'s job — and makes no enforcement decisions of its own. It only
carries out an already-made decision: contain via [Action Broker](action-broker.md), export via
OTel/[Integrity Exporter](integrity-exporter.md). The module is kept deliberately dumb so a
routing bug can never also become a false-enforcement bug.

`handle()` runs five steps, in this exact order, for every event:

1. **Registry touch.** If the event is an `AgentEvent`, `self.registry.touch(event.agent.agent_id)`
   records that a known agent was observed again (see [Device Context](../entities/device-context.md)).
2. **Tier 1 evaluation.** `decision = self.policy_engine.evaluate(event, self._context())` — see
   [Policy Engine](policy-engine.md).
3. **Tier 2 SLM escalation (optional).** If `self.slm_backend` is not `None` *and* Tier 1's
   decision was `escalate`, the event is re-evaluated by the SLM backend and its decision
   replaces Tier 1's. See [SLM Cascade Tiers](slm-cascade-tiers.md) for what backend is actually
   wired up. A raised exception here is caught and logged; the router falls back to keeping
   Tier 1's decision rather than losing the event.
4. **Containment — FIRST, before anything else that could touch the network.** If an
   `ActionBroker` is configured and the (possibly Tier-2-revised) decision's action is
   `contain`, the router extracts a pid from the event and calls
   `self.action_broker.contain(pid)` with no `timeout_seconds` — a freeze-only call, because a
   timeout would block the router for however long that timeout is, which is exactly the delay
   a real-time enforcement path must never have. Containment is local, in-process, OS-signal-
   based, and effectively instant. It is not gated on export succeeding or even being attempted.
5. **Guardrail hooks (AgentEvent only).** Each configured hook is called with `(event, decision)`;
   an exception from a hook is logged and swallowed, matching the "a gate bug must not brick the
   session" posture the hooks themselves document. See [Guardrail Hooks](guardrail-hooks.md).
6. **Two independent, best-effort export paths**, merged into one `ExportStatus`:
   - An OpenTelemetry span via `integrity_sdk.telemetry.tracing.get_tracer("xibalba-shield")`,
     which always fires.
   - When an exporter is configured, the [Integrity Exporter](integrity-exporter.md)'s
     `export_event`/`export_decision` calls, which build and submit a real signed BCC
     commitment.

   These run in separate `try`/`except` blocks on purpose: a slow or unreachable
   `bcc_middleware` failing the exporter call must never suppress the OTel span, and a
   tracer/exporter-shim bug must never suppress the signed-commitment attempt. Results from
   both paths accumulate into a single `ExportStatus(attempted, event_exported,
   decision_exported, authorized, reason)` rather than one path overwriting the other's outcome.
7. **Event log.** If an `EventLog` is configured, the finished decision (including its
   `ExportStatus`) is appended. See [Event Log](../entities/event-log.md).

```python
def handle(self, event: NormalizedEvent) -> PolicyDecision:
    ...
    decision = self.policy_engine.evaluate(event, self._context())
    if self.slm_backend is not None and decision.decision.action == "escalate":
        decision = self.slm_backend.evaluate(event, self._context())      # Tier 2, opt-in
    if self.action_broker is not None and decision.decision.action == "contain":
        self.action_broker.contain(pid)                                   # freeze-only, no timeout
    for hook in self.guardrail_hooks:
        hook(event, decision)                                             # AgentEvent only
    # OTel span + optional Integrity Exporter, independent try/except blocks
    ...
    return decision
```

## Two speed classes, deliberately kept separate

Containment (step 4) is local, synchronous, and effectively instant. Evidence export (step 6) is
comparatively slow — a real BCC submission has been measured at 200–700ms against a live
`bcc_middleware` — and runs strictly after containment, so evidence-export latency can never
delay the actual protective action.

## `guardrail_hooks` is accepted but not populated by `shield run`

`EventRouter.__init__` accepts `guardrail_hooks: Iterable[Callable[[AgentEvent, PolicyDecision],
None]] = ()` — an optional parameter the router will call if supplied. `shield run`'s CLI does
not pass any by default. This is intentional, not an oversight: `shield run`'s sensor loop
observes OS-level telemetry (process/file/network), it does not simulate an agent runtime calling
tools, so there is nothing for a guardrail hook to wrap in that loop. See
[Guardrail Hooks](guardrail-hooks.md) for the full reasoning and the asymmetry with
[Action Broker](action-broker.md), which *is* wired into `shield run`'s live loop by default.

## `_pid_of`: why AgentEvent never gets contained here

```python
def _pid_of(event: NormalizedEvent) -> int | None:
    process = getattr(event, "process", None)
    return getattr(process, "pid", None)
```

Only `ProcessActivity`/`FileActivity`/`NetworkFlow` carry a `process.pid`. `AgentEvent` has no OS
process of its own — its `contain`/`escalate` actions are meant to be handled by the guardrail
hooks that wrap an agent's own tool calls, not by Action Broker.

## Restoration note

A 2026-08-07 refactor briefly replaced the Integrity Exporter with OTel-only telemetry, leaving
Shield with no path to a signed commitment. It was restored 2026-08-12 and now runs alongside
(not instead of) the OTel span — both independent, best-effort paths, as described above.

## Related pages

- [Policy Engine](policy-engine.md) — Tier 1, what actually produces `decision`
- [Action Broker](action-broker.md) — the containment call in step 4
- [Guardrail Hooks](guardrail-hooks.md) — step 5, and why they're not wired into `shield run`
- [Integrity Exporter](integrity-exporter.md) — the signed-commitment half of step 6
- [SLM Cascade Tiers](slm-cascade-tiers.md) — step 3 in full
- [Enforcement Pipeline](../architecture/enforcement-pipeline.md) — the end-to-end diagram
