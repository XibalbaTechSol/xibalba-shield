---
title: Action Broker
acronyms: []
created: 2026-08-12
updated: 2026-08-12
type: concept
tags: [containment, enforcement]
confidence: high
source_files:
  - shield/agent_core/action_broker.py
  - shield/agent_core/router.py
  - shield/cli.py
  - docs/audits/2026-08-07-action-broker.md
---

## Table of contents

- [Overview](#overview)
- [Containment methods](#containment-methods)
- [Wired into shield run's live loop as of 2026-08-12](#wired-into-shield-run-s-live-loop-as-of-2026-08-12)
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
