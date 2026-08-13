---
title: Shield Detection Quality Metrics
acronyms: [ADR, DID, BCC, AIS]
created: 2026-08-13
updated: 2026-08-13
type: concept
tags: [compliance]
confidence: high
source_files:
  - docs/pilot-acceptance-metrics.md
  - shield/integrity_exporter/exporter.py
  - shield/backend/store.py
  - shield/backend/api.py
  - scripts/burn_in.py
---

## Table of contents

- [Overview](#overview)
- [Metric boundary](#metric-boundary)
- [Canonical v1 metrics](#canonical-v1-metrics)
- [Evidence fields](#evidence-fields)
- [Synthetic and pilot labels](#synthetic-and-pilot-labels)
- [What's still open](#what-s-still-open)
- [Related pages](#related-pages)

## Overview

Shield should use Integrity Protocol for verifiable detection-quality measurement, not for
inline attack detection. The local Shield loop still senses, decides, and contains without a
cloud round trip. Integrity receives the signed decisions, telemetry, policy identifiers, and
operator or benchmark labels needed to reproduce quality metrics later.

The primary v1 metric is **Shield ADR**: Attack Detection Rate.

```text
Shield ADR = true_positive_security_decisions / labeled_malicious_events
```

`true_positive_security_decisions` means events labeled malicious by a trusted pilot review,
red-team run, benchmark harness, or explicit synthetic fixture where Shield returned `deny`,
`contain`, or a justified `escalate`.

## Metric boundary

Shield owns local evidence production:

- normalized event records
- policy decisions
- policy version/hash
- local export status
- review labels where an operator or benchmark supplies them

Integrity owns evidence aggregation and authoritative scoring:

- DID identity and signed BCC commitments
- accepted telemetry and anchor receipts
- queryable evidence surfaces
- any rollup score derived from Shield evidence

Shield must not compute AIS, persist AIS deltas as authoritative, or call private Oracle scoring
internals. A future "Shield Effectiveness Score" may be an Integrity Oracle/reporting output, but
Shield itself should expose only evidence-backed measurements and local summaries.

## Canonical v1 metrics

| Metric | Formula | Meaning |
|---|---|---|
| Shield ADR | `true_positive_security_decisions / labeled_malicious_events` | Share of labeled malicious events Shield detected with `deny`, `contain`, or justified `escalate`. |
| Blocking false-positive rate | `benign_events_blocked_or_contained / labeled_benign_events` | Share of labeled benign events that Shield blocked or contained. |
| Precision | `true_positive_security_decisions / all_deny_contain_escalate_decisions` | How often Shield's security decisions were actually malicious under labels. |
| Mean time to contain | `containment_timestamp - first_observed_timestamp` | Time from first observation to containment for contained malicious events. |
| Evidence export success | `successful_exports / export_attempted_decisions` | Share of decisions that became Integrity-accepted evidence. |

## Evidence fields

A metric sample is reproducible only when the underlying evidence includes:

- event ID
- device ID and tenant ID
- event class and observed timestamp
- policy version and policy hash
- decision action, rule ID, reason, and severity
- containment timestamp when action is `contain`
- export attempted/succeeded state
- BCC commitment or Integrity receipt when available
- label: `malicious`, `benign`, `ambiguous`, or `synthetic`
- label source: operator review, benchmark harness, red-team run, or synthetic fixture

These are metadata and labels, not raw prompts, file contents, secrets, credentials, patient
identifiers, or private documents.

## Synthetic and pilot labels

Synthetic data is useful for CI and demos, but it must remain explicitly labeled `synthetic`.
Pilot claims require pilot-window labels from real workloads, a benchmark harness, or a red-team
exercise. Synthetic ADR can prove wiring; it cannot prove production detection performance.

## What's still open

- The backend accepts typed detection-quality samples at `POST /api/shield/detection-quality`,
  and `scripts/burn_in.py` can compute the same aggregate metrics from labeled JSONL.
- The backend report surface at `POST /api/shield/detection-quality/report` recomputes raw and
  receipt-backed metrics, verifies BCC middleware `/v1/bcc/verify_token`, and optionally checks
  Oracle `/v1/audit-log` readback.
- A 2026-08-13 live smoke verified one ADR-counted Shield sample through both BCC token readback
  and Oracle audit-log readback on the local Integrity stack.
- Label provenance needs a signed or authenticated source model before detection-quality metrics
  should be used for customer-facing claims.
- Full oracle-signed compliance evidence export remains an `integrity-core` Phase C roadmap item,
  separate from Shield's receipt-verified ADR report.

## Related pages

- [Integrity Exporter](integrity-exporter.md) - how decisions become signed BCC commitments
- [Event Log](../entities/event-log.md) - local decision records and export status
- [Compliance Evidence Trail](../queries/compliance-evidence-trail.md) - audit posture and gaps
