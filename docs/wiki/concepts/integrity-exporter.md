---
title: Integrity Exporter
acronyms: [DID, BCC]
created: 2026-08-12
updated: 2026-08-28
type: concept
tags: [compliance, infrastructure]
confidence: high
source_files:
  - shield/integrity_exporter/exporter.py
  - shield/agent_core/router.py
  - shield/cli.py
---

The exporter passes `PolicyDecision.invocation_id` to SDK versions implementing Integrity's
`xibalba.invocation.v1` profile, causing it to be signed into the BCC commitment. During the
pinned-SDK migration, results also distinguish whether the ID was included in the signed
commitment; an unsigned local correlation value is not receipt-bound evidence.

## Table of contents

- [Overview](#overview)
- [Detection quality evidence](#detection-quality-evidence)
- [What it does on construction](#what-it-does-on-construction)
- [Two export methods, two different Integrity Protocol endpoints](#two-export-methods-two-different-integrity-protocol-endpoints)
- [Restored 2026-08-12](#restored-2026-08-12)
- [Local enforcement does not depend on export succeeding](#local-enforcement-does-not-depend-on-export-succeeding)
- [Related pages](#related-pages)

## Overview

`IntegrityExporter` (`shield/integrity_exporter/exporter.py`) turns a local
[Policy Engine](policy-engine.md) decision into signed evidence, using `integrity-core`'s
existing primitives with no privileged shortcut. It does not compute AIS — that remains
`integrity-oracle`'s scoring-core's job in the parent repo — and has no code path that bypasses
that rule.

## Detection quality evidence

The exporter is also the right bridge for Shield detection-quality metrics. Shield should emit
signed decisions, event telemetry, policy hashes, export status, and operator or benchmark
labels; Integrity should aggregate those records into reproducible metrics such as
[Shield ADR](shield-detection-quality-metrics.md), false-positive rate, precision, mean time to
contain, and export success. Shield still does not compute AIS or any authoritative security
score locally.

## What it does on construction

```python
class IntegrityExporter:
    def __init__(self, *, bcc_middleware_url: str, oracle_url: str | None = None,
                 agent_label: str = "xibalba-shield") -> None:
        self.agent_id, self.keypair, self.doc = sdk_did.load_or_create_did(agent_label)
        self._nonce_store = bcc.NonceStore(sdk_did.agent_dir(agent_label) / "bcc_nonce")
        self._telemetry_client = IntegrityClient(
            self.agent_id, oracle_url, keypair=self.keypair,
            auto_flush=True, background_flush=True,
        )
```

1. Loads or creates a DID/keypair via `integrity_sdk.did.load_or_create_did` — one identity per
   device/deployment, persisted so restarts don't mint a new DID each time.
2. Builds a real signed BCC commitment via `integrity_sdk.bcc.build_bcc_commitment` for every
   decision it exports.
3. Submits it to `bcc_middleware` (`bcc.submit_commitment`).
4. Submits raw event telemetry separately, through `IntegrityClient.log_telemetry` — the same
   public Integrity telemetry pipeline every other `integrity-sdk` integration uses.
5. Records export status on the `PolicyDecision` locally (via
   [Event Router](event-router.md)'s `ExportStatus` merge), so operators can see evidence gaps.

## Two export methods, two different Integrity Protocol endpoints

- **`export_decision(decision)`** — a `PolicyDecision` is a gating decision about whether
  something was allowed to happen. It maps `decision.decision.action` to one of a small, fixed
  table of `intent_type` values (`contain → agent_contained`, `deny → connection_blocked`,
  `escalate → guardrail_denied`, anything else → `device_posture_change`; `AgentEvent`
  `deny`/`escalate` always maps to `guardrail_denied`) and submits a BCC commitment via
  `POST /v1/bcc/intercept`-equivalent to `bcc_middleware` — deliberately a small explicit table,
  not a free-text passthrough, so the `intent_type` vocabulary stays pinned across packages.
- **`export_event(event)`** — raw sensor observations carry no gating decision of their own; they
  become evidence via `IntegrityClient.log_telemetry`.

Both are best-effort: a failed `bcc.submit_commitment` call is caught, logged loudly (never
silently swallowed), and returns `{"authorized": False, "reason": "submission failed: ..."}`
rather than raising into the caller.

## Restored 2026-08-12

A 2026-08-07 regression deleted this module in favor of OTel-only telemetry, leaving Shield with
no path to a signed commitment. It was restored on 2026-08-12 and now runs alongside — not
instead of — the OTel span [Event Router](event-router.md) always emits. One deliberate change
from the pre-deletion version: `IntegrityClient` is constructed with `background_flush=True` (the
SDK's own default), not the original `background_flush=False`. This is intentional: Shield's
decisions fire on a real-time enforcement path, and a `contain`/`deny` decision must not block on
a synchronous telemetry flush to a possibly slow or unreachable `bcc_middleware`.

## Local enforcement does not depend on export succeeding

[Action Broker](action-broker.md) containment (see [Event Router](event-router.md)'s step
ordering) happens before the exporter is ever called, and is not rolled back if export fails.
Export is downstream evidence propagation — it is never the authority deciding whether an action
is allowed. This is the load-bearing fact behind
[Compliance Evidence Trail](../queries/compliance-evidence-trail.md).

## Related pages

- [Event Router](event-router.md) — calls `export_event`/`export_decision`, merges the result
- [Policy Engine](policy-engine.md) — produces the decisions this module exports
- [Compliance Evidence Trail](../queries/compliance-evidence-trail.md) — what this evidence is
  and isn't sufficient for
- [Shield Detection Quality Metrics](shield-detection-quality-metrics.md) — how labeled Shield
  evidence supports ADR and false-positive measurement
