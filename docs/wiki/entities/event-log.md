---
title: Event Log
acronyms: []
created: 2026-08-12
updated: 2026-08-12
type: entity
tags: [compliance, infrastructure]
confidence: high
source_files:
  - shield/agent_core/eventlog.py
  - shield/cli.py
---

## Table of contents

- [Overview](#overview)
- [Optional HMAC hash-chain tamper evidence](#optional-hmac-hash-chain-tamper-evidence)
- [What this detects, and what it honestly does not](#what-this-detects-and-what-it-honestly-does-not)
- [Related pages](#related-pages)

## Overview

`EventLog` (`shield/agent_core/eventlog.py`) is the local JSONL decision log that backs `shield
status` and `shield events --recent`. It is deliberately a plain, appendable file rather than a
database — a plain file an admin can `tail`/`grep` without other tooling is the simplest thing
that meets the goal of a security product an admin can explain in one command.

```python
class EventLog:
    def __init__(self, path: Path, *, integrity_key_path: Path | None = None): ...
    def append(self, decision: PolicyDecision) -> None: ...
    def recent(self, n: int = 20) -> list[dict]: ...
    def count(self) -> int: ...
    def verify(self) -> dict: ...
```

[Event Router](../concepts/event-router.md) calls `event_log.append(decision)` as the last step
of every `handle()` call, if an `EventLog` was configured — the row written is the decision's
full `to_dict()`, including its `ExportStatus` from
[Integrity Exporter](../concepts/integrity-exporter.md).

## Optional HMAC hash-chain tamper evidence

When constructed with `integrity_key_path`, every appended row gets an `_integrity` block:

```python
{
    "algorithm": "sha256-chain+hmac-sha256",
    "previous_hash": "<prior entry's entry_hash, or empty for the first row>",
    "entry_hash": "sha256(previous_hash + canonical_json(row))",
    "hmac_sha256": "hmac_sha256(key, entry_hash)",
}
```

Each entry's hash chains to the previous entry's hash, and the whole chain is HMAC-signed with a
key read from `integrity_key_path`. `verify()` re-walks the file, recomputing each hash and HMAC
and checking `previous_hash` continuity, returning `{"ok": False, ...}` with the specific line and
reason on the first mismatch, edit, or truncation-continuity break. `shield --log-integrity-key
... run` enables writing this; `shield verify-log --integrity-key ...` runs the check.

## What this detects, and what it honestly does not

This detects edits, truncation-continuity breaks, and verification against the wrong key. It
does **not** stop root from deleting the log file, killing the Shield process before it can
write, or stealing the HMAC key — all of that remains honestly documented as an open limitation,
not papered over as "tamper-proof." See
[Compliance Evidence Trail](../queries/compliance-evidence-trail.md) for what this evidence is
and isn't sufficient for as an audit artifact.

## Related pages

- [Event Router](../concepts/event-router.md) — the sole writer, via `append()`
- [Compliance Evidence Trail](../queries/compliance-evidence-trail.md) — what local log evidence
  is and isn't sufficient for
