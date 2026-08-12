---
title: Compliance Evidence Trail
acronyms: [DID, BCC, SIEM]
created: 2026-08-12
updated: 2026-08-12
type: query
tags: [compliance]
confidence: medium
source_files:
  - shield/agent_core/eventlog.py
  - shield/integrity_exporter/exporter.py
  - shield/integrations/siem.py
  - shield/agent_core/router.py
---

## Table of contents

- [Open question](#open-question)
- [What exists today](#what-exists-today)
- [What's still open](#what-s-still-open)
- [The other half of this story lives in xibalba-cortex](#the-other-half-of-this-story-lives-in-xibalba-cortex)
- [Related pages](#related-pages)

## Open question

How does a `contain`/`deny` [Policy Engine](../concepts/policy-engine.md) decision become an
auditable record suitable for a finance/healthcare compliance review, today, with the code that
actually exists — and where does that chain of evidence still fall short of a real proof?

This is an open question, not a conclusion, per this wiki's `type: query` convention — it names
what's built and what's still genuinely undecided, without pretending the undecided parts are
resolved.

## What exists today

1. **Local JSONL decision log.** [Event Log](../entities/event-log.md) appends every finished
   `PolicyDecision` — including its `ExportStatus` — to a plain JSONL file. Optionally, each row
   carries a `sha256`-chained, HMAC-signed `_integrity` block (`shield --log-integrity-key ...`),
   verifiable with `shield verify-log`. This detects edits, truncation-continuity breaks, and
   verification against the wrong key.
2. **Signed BCC commitment path.** When [Integrity Exporter](../concepts/integrity-exporter.md)
   is configured and `bcc_middleware` submission succeeds, each `contain`/`deny`/`escalate`
   decision becomes a real, DID-signed BCC commitment submitted to `integrity-core`'s
   `bcc_middleware` — a cryptographically signed, externally-verifiable artifact, not merely a
   local file entry.
3. **Generic SIEM/SOAR export.** `shield siem-export` (`shield/integrations/siem.py`) can
   normalize the local decision log to JSONL for filebeat/fluent-bit/Splunk Universal Forwarder
   collection, or POST each decision to a generic webhook receiver. Both paths are real and
   tested; there is no proprietary or non-generic schema requirement on the receiving end.

## What's still open

- **No chosen downstream SIEM/SOAR consumer.** The generic webhook/JSONL export mechanism works,
  but no specific SIEM or SOAR product is a designated, integration-tested destination. An
  operator has to plug in their own receiver; there is no reference deployment this repository
  validates against.
- **Local log evidence is operational, not cryptographic, unless the exporter path actually
  succeeds.** A local JSONL log — even HMAC hash-chained — is useful operational evidence an
  admin can review, but it is not cryptographic proof: root on the endpoint can still delete the
  log, kill Shield before it writes, or steal the HMAC key (see
  [Event Log](../entities/event-log.md)'s honest limitations section). Integrity-anchored proof
  requires the [Integrity Exporter](../concepts/integrity-exporter.md)'s BCC submission to
  actually reach and be accepted by `bcc_middleware` — export is best-effort and can fail
  silently from a compliance reviewer's perspective unless they also check `ExportStatus`/export
  logs, not just the decision log itself.
- **The Tier-1 decision's own provenance has an open gap.** [Policy Engine](../concepts/policy-engine.md)
  delegates matching to a local OPA sidecar whose policy source is undefined in this repository —
  a compliance reviewer asking "which rule, sourced from where, produced this decision" cannot
  currently answer that from anything checked into `xibalba-shield` or `integrity-core`.

## The other half of this story lives in `xibalba-cortex`

This page intentionally shares its title with `xibalba-cortex`'s own
[`compliance-evidence-trail`](https://github.com/XibalbaTechSol/xibalba-cortex/wiki/compliance-evidence-trail)
page, so the two repositories' compliance stories read as one narrative. Shield produces the
real-time enforcement half and the evidence-export half (this page); Cortex provides the
queryable-history half — how an already-exported record gets searched, retrieved, and presented
for a review, after Shield has produced it.

## Related pages

- [Event Log](../entities/event-log.md) — the local half of this trail
- [Integrity Exporter](../concepts/integrity-exporter.md) — the signed, externally-verifiable half
- [Policy Engine](../concepts/policy-engine.md) — the open provenance gap named above
- [Enforcement Pipeline](../architecture/enforcement-pipeline.md) — where this evidence is produced
