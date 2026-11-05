---
title: Action Broker
acronyms: []
created: 2026-08-12
updated: 2026-11-05
type: concept
tags: [containment, enforcement]
confidence: high
source_files:
  - shield/agent_core/action_broker.py
  - shield/agent_core/protected_processes.py
  - shield/agent_core/router.py
  - shield/cli.py
  - shield/agent_core/outcome_log.py
  - docs/audits/2026-08-07-action-broker.md
---

## Table of contents

- [Overview](#overview)
- [Containment methods](#containment-methods)
- [Protected-process interlock](#protected-process-interlock)
- [Wired into shield run's live loop as of 2026-08-12](#wired-into-shield-run-s-live-loop-as-of-2026-08-12)
- [Commissioning instrumentation and the resume path](#commissioning-instrumentation-and-the-resume-path)
- [Verification record](#verification-record)
- [Related pages](#related-pages)

## Overview

`ActionBroker` (`shield/agent_core/action_broker.py`) is real OS-level process containment. It is
deliberately separate from policy evaluation: a caller supplies an already-authorized action, and
the broker performs only the narrow OS operation requested. It does not read policy, does not
decide what "contain" means for a given event, and has no dependency on
[Policy Engine](policy-engine.md) — that separation exists so a containment bug can never also
become a policy-evaluation bug, and vice versa.

## Containment methods

```python
class ActionBroker:
    def freeze(self, pid, *, cgroup_path=None) -> ActionResult: ...
    def resume(self, pid, *, cgroup_path=None) -> ActionResult: ...
    def escalate_to_kill(self, pid, *, timeout_seconds, cgroup_path=None) -> ActionResult: ...
    def contain(self, pid, *, timeout_seconds=None, cgroup_path=None) -> ActionResult: ...
```

- **`freeze(pid)`** — resumable containment. Without a `cgroup_path`, sends `SIGSTOP`. With a
  `cgroup_path`, writes `"1\n"` to that cgroup's `cgroup.freeze` file (cgroup v2 freezer, for
  containerized agents).
- **`resume(pid)`** — the inverse: `SIGCONT`, or `"0\n"` to `cgroup.freeze`.
- **`escalate_to_kill(pid, timeout_seconds=...)`** — waits out the caller-supplied timeout, then
  sends `SIGKILL`. This is the *only* code path that can terminate a process. It does not poll
  process state; a broker caller owns the policy decision and the timeout, and the wait is
  explicit rather than an implicit fallback.
- **`contain(pid, timeout_seconds=None)`** — the convenience entry point: freezes immediately,
  and only escalates to `SIGKILL` if a `timeout_seconds` is given. Called with no timeout,
  `contain()` is freeze-only and returns as soon as the signal is sent.

`SIGKILL` is never the primary or default action — it only fires from an explicit timeout
escalation, never as a direct response to a `contain` decision.

## Protected-process interlock

`ProtectedProcessGuard` (`shield/agent_core/protected_processes.py`) runs **inside** the broker's
`freeze`, `kill_process`, `escalate_to_kill`, and `freeze_cgroup` paths, so no caller can bypass
it. It is on by default; there is no disable switch. A refusal raises `ProtectedProcessError`
*before any signal is sent*; the router records it as a failed containment
(`EnforcementOutcome.completed=False`). `resume` is never guarded: recovery must always work.

Protected: pid <= 1, Shield's own pid and every ancestor, explicit `extra_pids`, and system
binaries (`sshd`, `systemd`, `dbus-daemon`, `containerd`, `dockerd`, `opa`, `shield`, ...).
Identity is the resolved `/proc/<pid>/exe`, not `comm`/argv (a process can rename itself), and a
name match counts only if the binary sits under a root-owned directory (`/usr/sbin/`, ...), so a
copy named `sshd` in `/tmp` gets no immunity. A cgroup freeze is refused if any member is
protected or membership is unreadable.

Fail posture: **closed**. A live process whose exe cannot be read is treated as protected.
Limits: with no `/proc` (Windows/macOS) only the pid-based rules apply; name-based protection
there is `[PLANNED]`. This changes no default (`--enforcement-mode` is still `enforce`).

## Wired into `shield run`'s live loop as of 2026-08-12

`shield/cli.py`'s `run` subcommand constructs a real broker by default:

```python
action_broker = None if args.no_containment else ActionBroker()
router = EventRouter(..., action_broker=action_broker, ...)
```

[`EventRouter.handle()`](event-router.md) calls `self.action_broker.contain(pid)` — freeze-only,
no timeout — as the very first thing it does for a `contain` decision on a process-related event,
before anything else in the method, including any network call. `--no-containment` opts out for
local-only observation/dev use, the same purpose `--no-exporter` serves for the
[Integrity Exporter](integrity-exporter.md).

## Commissioning instrumentation and the resume path

Added 2026-11-05 so the commissioning ladder has measurable evidence.

- **`EnforcementOutcome.handle_to_contain_ms`**: monotonic milliseconds from `EventRouter.handle()`
  entry to `ActionBroker.contain()` returning. It is `None` for a failed containment, never a fast
  number. It is **not** sensor-event-to-freeze: event timestamps are whole-second, so that
  figure would be fabricated. Sub-second sensor timestamps are `[PLANNED]`.
- **`shield resume --pid N [--event-id E] [--device-config PATH]`**: the operator rollback path.
  It `SIGCONT`s the process and, when a device config is given, records an `action: "resume"`
  outcome whose `resumes_event_id` names the freeze reversed. Before this command, `resume` had
  no caller in the product. The resume itself never waits on the backend; if the outcome cannot be
  recorded the command says so and the resume does not count toward the metric.
- **Local outcome log (`outcomes.jsonl`)**: `shield run` also appends every outcome, now carrying `pid`,
  to a 0600 file beside the decision log (`LocalOutcomeLog`, bounded by one-backup rotation, best-effort).
  `shield resume` writes its reversal there too. The [Device App](device-app.md) reads it.
- **`GET /api/shield/commissioning-metrics?tenant_id=&device_id=`** (admin): latency p50/p95/p99
  (nearest-rank), containment counts, false-freeze rate (linked resumes over completed freezes),
  and observe-mode would-actions. Every figure is `None`, not 0, when its inputs do not exist, and
  the response lists what is `not_instrumented`. The window is the latest 5,000 outcome rows.

## Verification record

`docs/audits/2026-08-07-action-broker.md` records: `111 passed, 9 skipped` at closure, injected
signal calls and temporary freezer files for unit tests, and notes that "privileged live host
validation remains a deployment exercise" — the broker's logic is unit-tested, not yet exercised
against a real running target process on a live host as part of this repository's own test
suite.

## Related pages

- [Event Router](event-router.md) — the caller; documents exact call ordering
- [Policy Engine](policy-engine.md) — produces the `contain` decision the broker acts on
- [SLM Cascade Tiers](slm-cascade-tiers.md) — a Tier-2-revised `contain` decision still routes
  through this same broker, never through Tier 2's own logic
