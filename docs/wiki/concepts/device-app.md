---
title: Device App
acronyms: []
created: 2026-11-05
updated: 2026-11-05
type: concept
tags: [device, console, containment]
confidence: medium
source_files:
  - device-app/device-core/src/lib.rs
  - device-app/device-core/tests/contract.rs
  - device-app/src-tauri/src/lib.rs
  - device-app/src/App.jsx
  - device-app/src/bridge.js
  - shield/agent_core/outcome_log.py
  - shield/cli.py
  - tests/test_device_contract.py
---

## Table of contents

- [Overview](#overview)
- [Data flow](#data-flow)
- [What is verified](#what-is-verified)
- [Known gaps](#known-gaps)
- [Related pages](#related-pages)

## Overview

The device app (`device-app/`) is a Tauri tray application for the endpoint. It answers "what has
Shield frozen on this machine, and how do I undo it?" and is the operator's local observer and
manual override. It reads Shield's logs, checks them against the operating system, and runs
`shield resume`. It never signals a process itself.

## Data flow

1. `shield run` writes `decisions.jsonl` ([Event Log](../entities/event-log.md)) and, since
   2026-11-05, `outcomes.jsonl` through `LocalOutcomeLog` (`shield/agent_core/outcome_log.py`),
   beside the backend publisher, isolated from it by `fan_out`. Outcomes now carry `pid`.
2. `device-core` (plain Rust) reads the bounded tail of both files and derives the open freezes:
   a freeze is reversed by a later completed resume naming its `event_id`, or targeting the same pid.
3. Each open freeze is **checked against `/proc/<pid>/stat`**: *stopped* (confirmed), *running*
   (the log says frozen, the OS disagrees), *gone*, or *unknown* (no `/proc`). The headline counts
   only confirmed stops.
4. Resume builds `shield resume --pid N --event-id=E ...` as an argument vector (pid validated,
   event id restricted so it cannot be read as an option) and the shell spawns it directly.

`shield resume` always appends a `resume` outcome to the local log, and tells the backend too when a
device config is available, which is what feeds the fleet false-freeze rate in
[Commissioning Ladder](commissioning-ladder.md).

## What is verified

- `device-core`: 19 unit tests and 3 contract tests (`cargo test`).
- Contract: the Rust reader is tested against golden fixtures produced by the real Python
  `EventRouter`/`EventLog`/`LocalOutcomeLog`; `tests/test_device_contract.py` fails if the Python
  shape drifts from what the reader relies on.
- UI: 8 Playwright specs drive the real bridge by providing `window.__TAURI_INTERNALS__`.

## Known gaps

- **`src-tauri` (tray, window, commands) has not been compiled or run.** It needs the platform
  webview libraries; the build sandbox lacked them. Treat it as unverified.
- Without `/proc` (Windows, macOS) freeze state shows as *Unverified*. Those platforms are untested.
- The local outcome log is a best-effort convenience view, not the enforcement record: a failed
  write leaves a freeze missing from it.
- CI does not yet run `cargo test` or the app's Playwright specs.

## Related pages

- [Action Broker](action-broker.md)
- [Commissioning Ladder](commissioning-ladder.md)
- [Event Log](../entities/event-log.md)
