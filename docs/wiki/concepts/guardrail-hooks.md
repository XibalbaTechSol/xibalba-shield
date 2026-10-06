---
title: Guardrail Hooks
acronyms: []
created: 2026-08-12
updated: 2026-10-06
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
  - shield/gate_daemon.py
  - shield/agent_core/router.py
  - shield/cli.py
---

## Table of contents

- [Overview](#overview)
- [These are library calls an agent runtime makes — not a sensor loop](#these-are-library-calls-an-agent-runtime-makes-not-a-sensor-loop)
- [The out-of-process gate: shield gate-daemon](#the-out-of-process-gate-shield-gate-daemon)
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

## The out-of-process gate: `shield gate-daemon`

The section above is about in-process library calls. There is one deliberate exception that *is*
a background process: `shield gate-daemon` (`shield/gate_daemon.py`), which answers a harness's
`PreToolUse` question over a Unix socket. It exists because a harness hook is a short-lived
process spawned once per tool call, and cannot hold a warm [Policy Engine](policy-engine.md) —
constructing one means installing a verified pack into OPA, far too slow to repeat per call.
(docs/EXECUTION_PLAN.md B2 in `integrity-core`; until it existed, that repository's
`integrity hooks install --gate shield` was refused outright rather than silently falling back.)

**What it decides.** Only the Tier 1 verdict: `PolicyEngine.evaluate` against the verified pack,
nothing else. It deliberately does **not** go through `EventRouter`. `handle()` calls
`ActionBroker.contain()` — a real SIGSTOP — for a `contain` decision, which is the wrong
response to a tool call that has not run yet, and the router needs the whole exporter, event log,
SLM, Jev and memory stack that a gate has no use for. `contain` and `escalate` therefore collapse
to a denial of the one pending call, the same choice `guard_tool_call` makes; the real verdict
stays visible in the response's `action` field.

**Wire contract (v1).** One newline-terminated JSON object per connection, one response, then
close: request `{"v":1,"event":"pre_tool_use","agent_id","tool_name","tool_input_sha256"}`, response
`{"v","decision":"allow"|"deny","checked","action","enforced","reason","rule_id",
"policy_version","policy_hash","invocation_id"}`. `policy_hash` is the enforced pack's hash, so a
caller can record *which* policy ruled. Requests are capped at 4 MiB.

**Fail-closed, and where fail-open actually lives.** The daemon fails closed: an OPA outage, a
missing pack, a malformed request or an unexpected evaluator error all deny in enforce mode.
The fail-open tradeoff sits one layer out, in `integrity_sdk.hook_runner`, which lets the harness
proceed with `checked: False` if the daemon is unreachable. An unchecked allow is never an
authorized one. `--enforcement-mode observe` always answers `allow` while reporting, in
`action` with `enforced: false`, what it would have enforced.

**Operational facts worth knowing before wiring it up.**

- **Register the agent.** The registry is in-memory and starts empty, and every shipped pack
  denies tool activity from an unregistered agent (for example `smb-deny-unregistered-agent-tools`).
  With no `--register-agent`, denying every call is the daemon working as designed.
- **The socket is created `0600`**, with the umask set before bind so there is no window in which
  another local user can connect.
- **The tool's input never crosses the socket.** The request carries `tool_input_sha256` (64
  lowercase hex, or `uncanonicalizable`), because nothing in evaluation reads tool content — the
  event carries only the tool *name*. A stray raw `tool_input` field is ignored and never logged.
  The digest is validated with `fullmatch`, since it lands in an audit log line and Python's `$`
  would otherwise accept a trailing newline, letting a client forge a second log entry.
- **Path length.** AF_UNIX paths are limited to roughly 100 bytes; an over-long path fails with a
  message naming the length. Set `--socket` or `XIBALBA_SHIELD_GATE_SOCKET` to a shorter one.
- **SIGTERM stops it cleanly** and removes the socket; a stale socket from a crash is detected
  and replaced at the next start, while a *live* one is refused rather than taken over.

**`[PLANNED]` — not built.** The daemon does not yet emit a signed, chained receipt per decision;
that is the remaining half of B2's "signed chained receipts with checkpoints." The evaluator is a
parameter of `evaluate_pre_tool_use` so a receipt-emitting one can be substituted without
rewriting the module. Nor does `integrity_sdk.hook_runner` yet speak to this socket — its
`SUPPORTED_GATES` still names only `bcc`.

## Related pages

- [Event Router](event-router.md) — where `guardrail_hooks` is consumed, and the CLI wiring gap
  documented above
- [Action Broker](action-broker.md) — the counter-example that *is* wired into the live loop
- [Policy Engine](policy-engine.md) — every hook's underlying decision source
