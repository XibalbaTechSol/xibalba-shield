# Xibalba Shield Wiki — Log

## [2026-08-28] update | Per-attempt invocation correlation

- Added canonical UUID `invocation_id` to agent events, policy decisions, export status, and
  Integrity-export integration.
- Upstream agent IDs are preserved; endpoint-only observations receive a new UUID. Export
  failure does not remove the local ID.
- The pinned Integrity SDK remains feature-detected during rollout, and results distinguish
  whether the ID was included in the signed commitment.

## [2026-08-21] update | CLI Tier-2 backend wiring

- Wired `shield run --slm-backend {none,simulated,local}` through the live CLI runtime into
  `EventRouter`, matching the existing router-level Tier-2 contract.
- Added CLI regression coverage proving `--slm-backend simulated` revises a Tier-1 `escalate`
  decision and records `tier2` provenance. The simulated backend remains explicitly synthetic.
- Current root-free validation: 138 passed, 9 skipped.

## [2026-08-13] update | Rego policy bundle coverage

- Added interpreter-backed Rego translations for the professional-services and regulated default
  policy bundles and corrected SMB first-match precedence plus absent-registration handling.
- Focused verification: 7 Shield policy tests passed; individual Rego files passed `opa check`.
- The local runtime still requires an OPA sidecar and deliberate vertical/profile selection; those
  deployment/runtime gaps remain open.

## [2026-08-13] update | Supervised local OPA profile runner

- Added `shield/opa_local.py` and the explicit `shield local-run --profile {smb|professional-services|regulated}` smoke command.
- The launcher selects exactly one allowlisted Rego bundle, binds to a dedicated loopback port, performs a profile-specific rule probe, detects early OPA exit, and terminates the child process on exit.
- The selected Rego file's SHA-256 hash is carried into Shield policy metadata and printed at startup.
- Verification: 32 focused tests passed; each Rego file passed independent `opa check`; real `local-run --profile smb --max-events 1` processed 1 event and exited successfully.
- This is local smoke/runtime hardening, not production supervision, deployment readiness, Windows lifecycle proof, or live Integrity export. The existing local exporter attempts reported HTTP 404 because no compatible local Oracle endpoint was running; export was disabled for the smoke command.


> Chronological record of wiki actions. Append-only — never edit past entries.
> Actions: ingest, create, update, lint, query, archive

## [2026-08-13] update | Detection quality metrics

- Created `concepts/shield-detection-quality-metrics.md` to define Shield ADR, false-positive
  rate, precision, mean time to contain, and evidence export success as labeled-evidence metrics.
- Updated the wiki home, index, and Integrity Exporter page to make the boundary explicit:
  Shield emits/verifies local evidence; Integrity aggregates and reports detection quality;
  Shield does not compute AIS.
- Added backend ingestion and burn-in aggregation for typed detection-quality samples.
- Added receipt-verified detection-quality reporting and ran a live local smoke against BCC
  `/v1/bcc/verify_token` plus Oracle `/v1/audit-log`; full oracle-signed evidence export remains
  an `integrity-core` Phase C item.

## [2026-08-12] create | Initial Shield wiki

- Seeded the initial `docs/wiki/` content tree for `xibalba-shield`, following the schema and
  conventions established in the sibling `integrity-core` repository's wiki.
- Wrote 7 concept pages: the enforcement pipeline's event router, the policy engine, the action
  broker, guardrail hooks, the Integrity exporter, the SLM cascade tiers, and the sensor model.
- Wrote 2 entity pages: device context/agent registry (merged onto one canonical page per the
  no-duplication rule — `AgentRegistry`'s distinct surface was too thin to justify a separate
  page), and the local event log.
- Wrote 2 architecture pages: the ecosystem role (Shield as the Immune System in the
  three-repository ecosystem) and the end-to-end enforcement pipeline diagram tying the four core
  concept pages together.
- Wrote 1 query page: the compliance evidence trail, sharing its title with `xibalba-cortex`'s
  own page of the same name so the two repositories' compliance stories read as one narrative.
- Wrote `WIKI_SCHEMA.md`, `WIKI_INDEX.md`, and `index.md`, adapted from `integrity-core`'s wiki
  format for Shield's domain and tag taxonomy.
- Notable finding surfaced during this pass, documented on `concepts/policy-engine.md`: the
  committed `shield/policy_engine/engine.py` (as of commit `f86c0f0`, 2026-08-07, unchanged
  since) delegates rule evaluation to a local OPA sidecar rather than the table-driven in-process
  matcher `README.md` and `CLAUDE.md` still describe, and no `.rego` policy source for
  `shield/policy` exists in this repo or in `integrity-core` — flagged as a real, current
  documentation-vs-code drift rather than silently following the stale description.
- Ran `python3 scripts/wiki_toc.py` to generate every page's `## Table of contents` block, then
  verified with `python3 scripts/wiki_toc.py --check`.

## [2026-08-25] update | Packaged local OPA profile smoke path

- Moved the three Rego profiles into `shield/policies/rego/` and declared them as package data so
  `shield local-run` works from a built wheel outside a source checkout.
- Hardened local supervision: Open Policy Agent (OPA) output no longer uses unread pipes, missing
  binaries return a concise nonzero CLI result, and Continuous Integration pins OPA 1.18.2 with
  SHA-256 checksum verification instead of downloading `latest` without integrity checking.
- Verification: focused CLI/OPA tests `27 passed`; full root-free suite `139 passed, 10 skipped`;
  all three Rego files passed `opa check`; all three JSON bundles passed `shield validate`; a wheel
  built, installed under `/tmp`, and processed one real selected-profile event from outside the
  repository. Skips remain the suite's explicit root/live-dependency checks.
## [2026-08-22] update | Professional-services combined-condition regression

- Added a real-OPA, table-driven `PolicyEngine.evaluate()` regression for the professional-services
  profile using normalized `AgentEvent` inputs that carry agent, context, and activity fields.
- Covered ordered evidence for overlapping conditions: unregistered agent denial before unapproved
  endpoint and client-data context, unapproved endpoint denial before client-data escalation after
  registration, and client-data escalation after registration plus approved endpoint.
- Updated `concepts/policy-engine.md` to document the regression boundary: existing Rego semantics
  only, no policy-language change, no credentials, and no mocked OPA decision path.
