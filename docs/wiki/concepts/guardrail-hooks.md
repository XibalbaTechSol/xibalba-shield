---
title: Guardrail Hooks
acronyms: []
created: 2026-08-12
updated: 2026-11-12
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
  - shield/gate_receipts.py
  - shield/gate_zone.py
  - shield/sensor_status.py
  - shield/watchdog.py
  - shield/agent_core/router.py
  - shield/cli.py
---

## Table of contents

- [Overview](#overview)
- [These are library calls an agent runtime makes — not a sensor loop](#these-are-library-calls-an-agent-runtime-makes-not-a-sensor-loop)
- [The out-of-process gate: shield gate-daemon](#the-out-of-process-gate-shield-gate-daemon)
  - [Signed, chained receipts (--receipt-dir)](#signed-chained-receipts-receipt-dir)
  - [The zone mask (--zone-mode)](#the-zone-mask-zone-mode)
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
"policy_version","policy_hash","invocation_id","receipt","receipt_status"}`. `policy_hash` is the
enforced pack's hash, so a caller can record *which* policy ruled. `receipt` and `receipt_status`
are the receipt fields described below; both are present on every response. Requests are capped
at 4 MiB.

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

### Signed, chained receipts (`--receipt-dir`)

With `--receipt-dir` the daemon writes one **signed, chained receipt per decision** before it
answers (`shield/gate_receipts.py`, a thin adapter over the SDK's shared writer `integrity_sdk.core.receipt_writer` since 2026-10-10; the format, signing domain, chain and checkpoint rules are
`integrity_sdk.core.receipts`, shared with BCC and with `integrity-cli`'s independent verifier —
Shield invents no receipt field). It is opt-in: without the flag the response says
`receipt_status: "disabled"`, never silence.

- **Files.** `receipts.jsonl` and `checkpoints.jsonl` in the directory, created `0600` (directory
  `0700`), each line `fsync`-ed before the harness is answered. A checkpoint commits to the Merkle
  root over the first `tree_size` receipts, every `--receipt-checkpoint-every` receipts (default
  100) and once more on a clean stop. A hard crash writes no final checkpoint; the periodic ones
  and the next start's verification cover that.
- **Keys.** `--receipt-key` (Ed25519 PEM, default `SHIELD_DEVICE_KEY_PATH`, never created if
  missing) signs; `--receipt-hmac-key-file` (at least 32 bytes) hides the device and the tool.
  Both must be mode `0600` or the daemon refuses to start. The tool *name* and the device id never
  appear in the file in the clear; the agent DID does. `log_id` is derived from the same HMAC
  (`default_log_id`) rather than from the device id — the first version embedded the raw device
  id there, which only a live run against the real file showed.
- **What a receipt records.** The *final* verdict: `PolicyEngine.evaluate_with_basis` returns a
  `DecisionBasis` (decision, reason code, controls, pack hash, event class) alongside the
  `PolicyDecision`, which carries no reason code. If the local risk gate hardens a verdict after
  the pack answered, the receipt says `deny` with `INTEGRITY_LOCAL_RISK_CONTAIN`/`_ESCALATE`, not
  the pack's `permit`. `contain` and `escalate` record as `deny`. Observe mode records `shadow`
  with the verdict it *would* have enforced. A request the daemon refused to parse gets
  `receipt_status: "skipped"` and no receipt, since there is no decision to record.
- **Failure posture.** *Starting* fails closed: a log that does not verify with the configured key
  (bad signature, gap, broken link, missing tail after a checkpoint, another device's log id, a
  rotated key) stops the daemon rather than being extended or replaced. The one exception is a
  torn final line — a crash mid-write — which was never acknowledged and is discarded with a
  warning. *Recording* is **strict by default**: if a receipt cannot be written, enforce mode
  denies the call, `receipt_status` is `"failed"` and an ERROR is logged, so an unrecorded decision
  never lets a tool call through. The cost is stated: a full disk or failing volume makes every
  call deny until the log is writable. `--lenient-receipts` lets the decision stand instead.
  Observe mode never blocks either way. A failed write never advances the chain, and a partial
  write is truncated away (if even that fails the writer disables itself).
- **Limits.** Deleting `checkpoints.jsonl`, or truncating both files consistently, is not
  detectable from the files alone — that is what anchoring a checkpoint (B4) closes. The log is
  held in memory and re-verified at start; rotation and incremental trees are `[PLANNED]`.
  Rotating either key starts a new log.

Verification is `integrity verify --receipts bundle.json --trusted-signer <key>` from
`integrity-cli`; the daemon prints its signer key at start. Not built: BCC's side of B2 (the same
receipts from `bcc_middleware`) and the shared conformance vectors.

`integrity_sdk.hook_runner --gate shield` speaks to this socket (integrity-core #166).

### The zone mask (`--zone-mode`)

Off by default. `shield/gate_zone.py` adds one check after the policy pack has answered: the
agent's control zone restricts which *class* of tool call may run. It needs no chain, token or
hosted oracle in the request path.

| Zone | Permits |
|---|---|
| green | read, draft, execute, escalate |
| yellow | read, draft, escalate |
| red | read, escalate |

- **Classes.** A tool name maps to `read`, `draft`, `execute` or `escalate`
  (`--zone-tool-class TOOL=CLASS`, over a short default map). A tool in no map is `execute`.
- **Only removes permission.** The mask acts only on a call the pack permitted. A pack denial keeps
  its own action, reason and reason code in every zone.
- **Modes.** `off` builds no mask and calls no provider. `shadow` allows everything and reports what
  it would have restricted (`zone_mask.restricted` in the response, an INFO log line, and the control
  `ais_zone_mask:shadow_restricted` on the receipt). `enforce` denies with reason code
  `AIS_ZONE_RESTRICTED`. `--enforcement-mode observe` still never blocks.
- **`enforce` is a paid feature and needs a signed entitlement.** Without one it runs as `shadow`
  and never blocks. The entitlement is a file the backend signs (`xibalba.shield.entitlement.v1`,
  `shield/entitlement.py`): tenant, device, plan, `zone_enforce`, and a validity window. The gate checks
  it locally on every decision and never calls home: `--zone-entitlement-file PATH` points at the file,
  and `--zone-entitlement-key BASE64` is a trusted signer and may be repeated. The device config
  equivalents are `gate_zone.entitlement_file` and `gate_zone.entitlement_keys`. A refreshed file is
  picked up without a restart, and expiry is checked against the clock, so a lapse takes effect when it
  happens. Under `enforce`, every receipt records `ais_zone_entitlement:<status>`, where status is one
  of `ok`, `missing`, `malformed`, `bad_signature`, `wrong_device`, `not_yet_valid`, `expired` or
  `plan`. The response's `zone_mask` carries both `mode` (the mode applied) and `requested_mode`.
  This is a licence check, not a security boundary: whoever owns the device can change the code.
  Design: `docs/superpowers/specs/2026-11-12-shield-plans-metering-design.md` §6.
- **Where the zone comes from.** A zone provider is a callable `agent_id -> zone`. Two ship:
  `static` (the default: `--zone`, `--zone-agent AGENT=ZONE`) and `ais` (below). Another scorer
  attaches with `register_zone_provider(name, factory)` or `--zone-provider package.module:factory`.
  A provider that raises or answers with something that is not a zone is `unknown` (yellow by
  default, `--zone-unknown-as`), never green.
- **The `ais` provider: the loop closed on the device.** `--zone-provider ais` scores each agent from
  this gate's own receipts with `integrity_sdk.core.ais_local` (profile
  `ais-local/receipts-compliance-1`): the share of pack denials in the agent's last
  `--zone-ais-window` (50) counted decisions, through the SDK's AIS formula and zone policy. No
  Oracle, chain or token is consulted. It needs `--receipt-dir` (the file it reads) and an explicit
  `--zone-ais-tier` (0-3; per agent with `--zone-ais-agent-tier AGENT=TIER`): the tier is never
  assumed. The mask's own denials are not counted, so red cannot keep itself red: an agent recovers
  by doing what its zone permits. Fewer than `--zone-ais-min-observations` (10) decisions is
  `unknown`, never a computed red. Receipts show the zone came from the score
  (`ais_zone_source:ais_local`, or `ais_local_cold_start`). Device config: `gate_zone.provider: "ais"`
  with a `gate_zone.ais` object (`default_tier`, `agent_tiers`, `window_size`, `min_observations`,
  `max_age_seconds`, `zone_policy`). Known limit: the agent id is the caller's, so a new id starts
  at cold start.
- **Sensor silence is a fault.** `shield run --sensor-status-file PATH` makes the watchdog write the
  sensor's health to a local 0600 file every tick. `shield gate-daemon --zone-sensor-status-file PATH`
  reads it on every decision; a stale (default 60 s), missing, unreadable or unhealthy status caps
  every agent's zone at red (`--zone-sensor-demote-to yellow` to soften). A gate with no status
  file configured is never demoted. The file is unsigned: it detects a sensor that died or was
  stopped, not one whose owner forges the file.
- **Receipts.** While the mask is on, every receipt carries the controls `ais_zone:<zone>`,
  `ais_action_class:<class>` and `ais_zone_source:<source>`. The receipt format is unchanged, so
  existing verifiers accept them.

The same settings can live in the device config as a `gate_zone` object; a flag overrides the
matching field. Not built: reading the Oracle's AIS (L1) as a provider; the `ais` provider uses only
local evidence.

### Usage reports and the backend ledger (`shield usage-report`)

Billing counts receipts, not requests, and never sits in the decision path. `shield usage-report`
reads the receipt log, verifies it, and sends one report per signed checkpoint to
`POST /api/shield/usage`: the range `[seq_from, seq_to]`, the counts `billable` /
`excluded_mask` / `excluded_fault` (the same exclusions as the AIS score), and the checkpoint
itself. The cursor (`usage_cursor.json`) advances only when the backend answers 2xx.

The backend (`shield/backend/usage_ledger.py`) accepts a report only if:

- the checkpoint verifies, and its signer is the key the device is **currently** registered with
  (`did:integrity:sha256(pubkey)` equals `devices.integrity_agent_id`). A device with no registered
  key gets 403, and so does a log signed by a key the device no longer holds;
- `checkpoint.log_id` matches, `checkpoint.tree_size == seq_to + 1`, and the counts sum to the range;
- the body names the device that authenticated.

The ledger, `usage_reports`, is keyed by `(tenant_id, log_id, seq_from)`. An identical replay is a
200 no-op. A different body for a stored range, or a range overlapping a stored one, is a 409. Gaps
are computed when read and never filled in. A reinstall is a new `log_id`, so it adds to the total.
Usage counts toward the month in which the backend **received** it. `GET /api/shield/usage?tenant_id=…&period=YYYY-MM`
(admin) returns per-device totals with synthetic devices left out, and every log's gaps. The split
between classes is self-reported. The checkpoint fixes the total and the content but not the
split; a later audit spot-checks it (design §3.4).

## Related pages

- [Event Router](event-router.md) — where `guardrail_hooks` is consumed, and the CLI wiring gap
  documented above
- [Action Broker](action-broker.md) — the counter-example that *is* wired into the live loop
- [Policy Engine](policy-engine.md) — every hook's underlying decision source
