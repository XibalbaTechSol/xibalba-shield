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

## [2026-08-29] update | Honest pilot-gate outcomes after runtime migration

- Reconciled the burn-in smoke constructor and no-exporter assertions with the packaged local
  Open Policy Agent runtime introduced on `main`.
- Restored the real signed BCC integration test in the end-to-end harness while preserving
  `PASS`, `SKIP`, and `FAIL` as distinct evidence states; an all-skipped pytest run is never
  reported as live success.
- Verification: full root-free suite `151 passed, 7 skipped`; `scripts/e2e_validate.py --json`
  completed with local loop, burn-in, kernel BTF, and all three policy profiles passing. Root
  eBPF, live BCC, and DID readback remained explicit skips because those dependencies were not
  available in this isolated run.

## [2026-08-31] update | Restore packaged local-run smoke after OPA supervision merge

- Fixed the `local-run` to shared-run namespace handoff by explicitly disabling the shared
  `--opa-command` supervisor when the selected-profile supervisor already owns Open Policy Agent.
- Added a command-level regression that reaches the enforcement loop and processes one synthetic
  event; before the fix it reproduced the hosted `AttributeError: Namespace has no attribute
  'opa_command'` failure.
- Verification: focused regression `1 passed`; full root-free suite `181 passed, 7 skipped`; all
  three default JSON policy packs validated; a built wheel installed under `/tmp` and processed
  one real `smb` profile event with Open Policy Agent 1.18.2; wiki table-of-contents check passed.

## [2026-09-08] update | README, remediation, reset delivery, and evidence boundaries

- Reconciled `README.md`, `SPECIFICATION.md`, and the canonical wiki with the current source
  and tests, without treating uncommitted implementation work as released capability.
- Added `concepts/exporter-remediation.md` for the authenticated queued lifecycle and the only
  supported endpoint actions: retry, flush, and reconnect. Arbitrary endpoint command execution
  remains out of scope.
- Documented SMTP password-reset configuration and its fail-closed API behavior: no raw reset
  token is returned, and failed delivery deletes the issued token and returns unavailable.
- Corrected the Linux sensor heading to match the archived Ubuntu 24.04 root evidence, while
  preserving the per-kernel support boundary in `docs/SUPPORTED_MATRIX.md`.
- Refreshed source-reviewed page dates, policy-profile provenance language, wiki counts, and
  navigation. Current test and table-of-contents results are recorded after validation below.

## [2026-09-08] update | Local mTLS and split-helper runtime repair

- Updated `README.md` and `docs/runbooks/linux-agent.md` with the local development mTLS
  control-plane procedure, credential boundaries, authenticated status readback, and the
  root-owned split-helper service relationship.
- Recorded the live gate in `docs/live-gate/split-helper-2026-09-08.md`: runtime status and
  remediation requests succeeded through `https://127.0.0.1:8443`; the endpoint then reported
  real process events, `sensors.attached=true`, `lost_events=0`, OPA healthy, and zero exporter
  failures.
- Updated the sensor and exporter-remediation wiki concepts with the verified TLS context and
  the runtime-directory ownership failure/fix. No new wiki pages were required.
- Remaining boundary: this is local Ubuntu/kernel evidence with a development CA, not a
  production PKI, reboot, or multi-kernel qualification.

## [2026-09-08] update | Proof-gated cgroup, kill, and network responders

- Added fail-closed configuration for cgroup v2 freeze, explicit process kill, and narrowly
  scoped nftables destination blocks. Flags cannot bypass missing assurance or runtime proofs.
- Added a fresh, root-owned, device-bound proof artifact contract and a disposable privileged
  runner that kills only its own canary, freezes and resumes only its own temporary cgroup, and
  creates then removes a unique nftables table.
- Published effective capabilities and the precise missing-proof count in the live responder UI;
  the console remains observational and cannot invoke or unlock destructive actions.
- Verification: 55 focused backend/responder tests passed; UI lint and production build passed;
  all 3 Chromium flows passed. Privileged host execution remains required before these three
  capabilities may be reported as ready.

## [2026-09-08] update | Comprehensive landing architecture and automated local access

- Expanded the landing journey with code-native Mermaid diagrams for the local decision path
  and fail-closed responder lifecycle, plus detailed operational-assurance content. Claims remain
  limited to implemented or explicitly proof-gated behavior.
- Added persistent first-boot generation for the backend super-admin token. Its value is stored
  mode `0600`, reused across restarts, and never printed.
- Added a development-only Vite authorization proxy and one-click local connection. The browser
  retains only a non-secret marker while the local server reads the tenant token and injects the
  authorization header; production builds do not expose this helper.

## [2026-09-08] update | Comprehensive landing architecture and automated local access

- Expanded the landing journey with code-native Mermaid diagrams for the local decision path
  and fail-closed responder lifecycle, plus detailed operational-assurance content. Claims remain
  limited to implemented or explicitly proof-gated behavior.
- Added persistent first-boot generation for the backend super-admin token. Its value is stored
  mode `0600`, reused across restarts, and never printed.
- Added a development-only Vite authorization proxy and one-click local connection. The browser
  retains only a non-secret marker while the local server reads the tenant token and injects the
  authorization header; production builds do not expose this helper.

## [2026-09-10] update | Restore local-run after Cortex option wiring

- Fixed the `local-run` to shared-run namespace handoff by initializing the optional Cortex URL
  and token fields before entering `_run`; the command continues to accept operator-provided
  `XIBALBA_CORTEX_URL` and `XIBALBA_CORTEX_TOKEN` through the provider's environment fallback.
- Reused the command-level enforcement-loop regression that reproduced the hosted
  `AttributeError: Namespace has no attribute 'cortex_url'` failure on `main`.

## [2026-09-12] lint | Restore deterministic wiki publication

- Regenerated `entities/device-context.md`'s table of contents after the Integrity and Cortex
  binding section was added out of heading order.
- `python3 scripts/wiki_toc.py --check` now reports all 14 canonical article TOCs current,
  closing the deterministic pre-publication check that blocked the GitHub Wiki sync workflow.
