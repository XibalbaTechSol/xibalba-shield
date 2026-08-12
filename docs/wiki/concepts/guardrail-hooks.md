---
title: Guardrail Hooks
acronyms: []
created: 2026-08-12
updated: 2026-08-12
type: concept
tags: [enforcement, compliance]
confidence: high
source_files:
  - shield/guardrail_hooks/ingress.py
  - shield/guardrail_hooks/retrieval_context.py
  - shield/guardrail_hooks/model_routing.py
  - shield/guardrail_hooks/output.py
  - shield/guardrail_hooks/tool_execution.py
  - shield/guardrail_hooks/post_action_verification.py
  - shield/agent_core/router.py
  - shield/cli.py
---

## Table of contents

- [Overview](#overview)
- [These are library calls an agent runtime makes — not a sensor loop](#these-are-library-calls-an-agent-runtime-makes-not-a-sensor-loop)
- [Related pages](#related-pages)

## Overview

`shield/guardrail_hooks/` is six real modules, one per semantic boundary an instrumented agent
runtime crosses. Each wraps a caller-supplied action with a policy check before (or, for one
hook, after) that action runs:

| Module | Hook point | Gates |
|---|---|---|
| `ingress.py` | 1 of 6 | request source and requesting identity, before any downstream work |
| `retrieval_context.py` | 2 of 6 | which data sources enter agent context |
| `model_routing.py` | 3 of 6 | model/provider/endpoint selection |
| `output.py` | 4 of 6 | caller-supplied output risk classification (`categories`, `risk_level`) |
| `tool_execution.py` (`guard_tool_call`) | 5 of 6 | concrete tool execution intent |
| `post_action_verification.py` | 6 of 6 | expected vs. actual state hash after an action already happened |

Each of the five pre-action hooks (everything but `post_action_verification`) constructs an
`AgentEvent`, routes it through a supplied `EventRouter`, and raises a hook-specific exception
(`IngressDenied`, `RetrievalDenied`, `ModelRoutingDenied`, `OutputBlocked`, `ToolCallDenied`) when
the resulting decision is not `allow`/`log_only` — so a caller can reject the request before the
guarded action runs. `verify_post_action` is structurally different: the action has already
happened by the time it runs, so it can only detect and produce evidence
(`contain`/`escalate`/`deny` signals a caller should react to reactively), never prevent
anything.

## These are library calls an agent runtime makes — not a sensor loop

This is the point most worth being precise about. The six hooks are functions an *instrumented
agent runtime* is expected to call explicitly at each of its own six semantic boundaries. They
are library code, not a background process.

`EventRouter.__init__` accepts an optional parameter:

```python
guardrail_hooks: Iterable[Callable[[AgentEvent, PolicyDecision], None]] = ()
```

`EventRouter.handle()` will call every hook in this list, for `AgentEvent` instances, as one of
its steps (see [Event Router](event-router.md)). But `shield/cli.py`'s `run` subcommand — the
command that runs Shield's live OS-level sensor loop — never passes a `guardrail_hooks` value.
It constructs `EventRouter(...)` without that argument, so the list is empty for every
`shield run` invocation.

**This is intentional, not a bug.** `shield run`'s sensor loop observes OS-level telemetry —
process exec, file write-open, TCP connect — via [Sensor Model](sensor-model.md)'s real or
synthetic sensors. It does not simulate an agent runtime making tool calls, choosing models, or
retrieving context, so there is nothing in that loop for a guardrail hook to wrap. Guardrail
hooks gate an *agent runtime's own semantic actions*; `shield run`'s sensor loop gates *OS-level
process/file/network activity* through [Policy Engine](policy-engine.md) and
[Action Broker](action-broker.md) directly, with no guardrail-hook involvement at all.

Contrast this explicitly with [Action Broker](action-broker.md), which **is** wired into
`shield run`'s live loop by default (`ActionBroker()` unless `--no-containment` is passed). The
asymmetry is deliberate: containment is something the sensor loop itself needs (a process it
observed misbehaving), while guardrail hooks are something only a caller building an
instrumented agent runtime on top of Shield's library would use — that caller constructs its own
`EventRouter` with `guardrail_hooks=[...]` and its own hook calls at the right points in its own
code, entirely outside `shield run`.

## Related pages

- [Event Router](event-router.md) — where `guardrail_hooks` is consumed, and the CLI wiring gap
  documented above
- [Action Broker](action-broker.md) — the counter-example that *is* wired into the live loop
- [Policy Engine](policy-engine.md) — every hook's underlying decision source
