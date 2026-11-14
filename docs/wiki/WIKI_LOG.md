# Xibalba Shield Wiki — Log

## [2026-11-14] ops | Render sandbox checkout passed; allowance measurement started

- A sandbox Pro checkout on the deployed service passed end to end. Webhooks were answered 200, and
  `/api/shield/billing/usage` reports the subscription period exactly as Stripe's items do.
- An observe-mode gate (`--zone-mode shadow --zone-provider ais`) now records real Claude Code tool
  calls on one workstation. The allowances are read out around 2026-12-14. Design doc §9 has the details.
- Added `scripts/e2e_billing_sandbox.py`, the test-clock harness behind the phase 3a–3d sandbox evidence.

## [2026-11-14] feat | Free-tier pressure on new enrollments (phase 3e)

- `shield/backend/free_tier.py`: free tenants over their included decisions are emailed once per
  month. After more than `free_over_periods` consecutive months over, new devices are refused (402).
  The free device cap is now enforced at enrollment as well.
- Decisions, uploads and enrolled devices are never affected. Re-enrollment always works.
- Off unless `SHIELD_FREE_TIER_PRESSURE=1`. The status shows as `free_tier` on `/api/shield/billing/usage`.
  Design doc §4.3 has the details.

## [2026-11-13] feat | Billing usage API aligned to the subscription period (phase 3e backend)

- `GET /api/shield/billing/usage?tenant_id=` (tenant admin): usage in the tenant's current billing
  period, counted exactly as the period close bills it. It returns seats, included, totals, remaining,
  overage decisions, accrued overage cents, per-device rows, gaps and `as_of`.
- `tenant_plans` gains `period_start` and `trial_end`, migrated in place. The webhook writes them, and the
  cycle-invoice close also moves the period forward.
- `period_counts` and `overage_for_period` are shared by the close and the page. Design doc §5 has
  the details.

## [2026-11-12] feat | The gate scores its agents from its own receipts (`--zone-provider ais`)

- New `ais` zone provider (`shield/gate_zone.py`, `AisReceiptZoneProvider`) over
  `integrity_sdk.core.ais_local`: decision -> receipt -> local AIS -> zone -> mask, on the device,
  with no Oracle, chain or token. Closes the AIS loop at L0.
- Flags: `--zone-ais-tier` (required), `--zone-ais-agent-tier`, `--zone-ais-window`,
  `--zone-ais-min-observations`, `--zone-ais-max-age`; device config `gate_zone.ais`. The receipts
  file is taken from `--receipt-dir`.
- CI's integrity-core pin bumped to the #208 merge (adds `ais_local`).
- Updated `concepts/guardrail-hooks.md`.

## [2026-11-05] update | Native Android Mobile Companion, Sideloadable APK, and Mobile Architecture

- Configured native Android build target (`aarch64-linux-android`) in Tauri v2 (`com.xibalba.shield.device`).
- Gated desktop-only system tray and window close APIs in `device-app/src-tauri/src/lib.rs` and `device-app/src-tauri/Cargo.toml` under `#[cfg(desktop)]` and enabled `#[cfg_attr(mobile, tauri::mobile_entry_point)]`.
- Assembled universal debug APK (`device-app/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk`) bundling `libshield_device_app_lib.so` in `arm64-v8a` (version code 1000, version name 0.1.0).
- Published `.github/workflows/build-mobile-android.yml` for automated CI artifact generation on GitHub Actions (`ubuntu-latest`).
- Formulated 3-pillar mobile security model for sandboxed OS environments: In-Process Agent Middleware SDK, Local Loopback VPN Tunnel (`VpnService`), and Mobile Companion UI with Android Keystore HSM DID anchoring (`did:integrity:...`) and biometric HITL escalation.
- Created operational runbook `docs/runbooks/android-agent.md`.

## [2026-11-05] update | Native macOS Support, Universal Desktop DMG, and LaunchDaemon Service

- Added cross-platform Apple Silicon & Intel Universal binary build pipeline (`.github/workflows/build-desktop-macos.yml`) producing `Xibalba Shield_0.1.0_universal.dmg` and `.app` bundles via Tauri v2.
- Implemented root Darwin LaunchDaemon packaging (`packaging/launchd/com.xibalba.shield.plist`) and runner wrapper (`packaging/launchd/xibalba-shield-run.sh`).
- Implemented automated root installer `scripts/install_macos_agent.sh` using Darwin `launchctl` service bootstrapping.
- Added Darwin kernel and subsystem compatibility adapters: POSIX `kill(pid, 0)` liveness probes in `device-core`, Darwin interface route detection (`en0`), strict 104-byte AF_UNIX socket length handling, and `ENOTSOCK` handling in `remove_stale_socket`.
- Added `macos-tests` runner matrix to CI (`.github/workflows/ci.yml`), passing all 765 tests on Apple Silicon `macos-14`.
- Created operational runbook `docs/runbooks/macos-agent.md`.


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

## [2026-10-04] update | Configurable advisory inference

- Added `concepts/advisory-inference.md`, documenting the implemented Jev, local-classifier, Lila
  JSON, and OpenAI-compatible provider adapters, validated settings, evidence sink, and failure
  boundary.
- Updated `WIKI_INDEX.md` and `index.md` to expose the new page.
- Source review covers `shield/policy_engine/inference.py`, `shield/policy_engine/jev_shadow.py`,
  `shield/backend/settings.py`, and `shield/cli.py` in the isolated implementation worktree.

## [2026-10-06] update | PreToolUse gate daemon (integrity-core B2)

- Added `shield gate-daemon` (`shield/gate_daemon.py`): a Unix-socket service answering a harness's
  `PreToolUse` question from a warm `PolicyEngine`. Documented in `concepts/guardrail-hooks.md`,
  whose "library calls, not a background process" section is now qualified by this one deliberate
  exception.
- Evaluates Tier 1 only and does not use `EventRouter`, since `handle()` runs a real SIGSTOP for
  `contain` and requires the full exporter/SLM/Jev stack. Fails closed; observe mode reports the
  verdict it would have enforced. Socket created `0600`. The wire contract carries a
  `tool_input_sha256` digest, never the tool input, which no part of evaluation reads.
- `[PLANNED]`: signed chained per-decision receipts (the other half of integrity-core B2), and
  `integrity_sdk.hook_runner` speaking to this socket — its `SUPPORTED_GATES` still names only `bcc`.
- Source review covers `shield/gate_daemon.py` and `shield/cli.py`. Verified against a real signed
  pack, real OPA and a real socket, not only stubs; the live run found and fixed two defects the
  in-process tests could not see (decisions were not being logged; SIGTERM left a stale socket).

## [2026-10-06] update | Advisory failure modes: reason codes, and a trace reader that detects tamper

- Closed integrity-core A7's second open item: a provider outage, malformed response, tenant mismatch
  and tamper no longer change enforcement **and say why**. `tests/test_jev_failure_modes.py` (81
  tests) proves the first differentially against a real OPA and signed pack, for a genuine deny and
  a `log_only` baseline, with the HTTP providers driven against a real local HTTP server.
- Added stable `reason_code`s to failed advisories (`ADVISORY_*`, in the log line and the stored row)
  and to the trace reader (`TRACE_*`). Documented in `concepts/advisory-inference.md`.
- Found and fixed four real defects while writing the tests, each confirmed by a probe against the
  actual code before any fix: (1) a provider's advice about a *different* event was stored as
  `available`; (2) `recommended_escalation: "false"` became `True`; (3) the trace reader trusted stored
  hashes, so rewriting only the **last** event went undetected; (4) any trace past 50 events was
  reported `valid: false` forever, because the 50-line window starts mid-chain.
- Tenant isolation in the reader was already correct; now pinned.
- Not done: the Settings UI (so A7's first open item stays open), a dashboard display of
  `reason_code`/`truncated`, and bounding the length of provider-returned `risk_category`, which is
  stored verbatim and is B5 territory. Tail/head truncation of a trace is undetectable from the file
  alone and needs an external anchor.

## [2026-10-07] update | Gate daemon emits signed, chained receipts (integrity-core B2)

- Added `shield/gate_receipts.py` (`GateReceiptWriter`) and `shield gate-daemon --receipt-dir`:
  one signed, chained receipt per decision, written and `fsync`-ed before the answer, with signed
  checkpoints every N receipts and on a clean stop. The format is `integrity_sdk.core.receipts`;
  Shield adds only the emitting side. Documented in `concepts/guardrail-hooks.md`.
- `PolicyEngine.evaluate_with_basis` returns the final `DecisionBasis` (reason code, controls, pack
  hash) a receipt needs; `evaluate` is unchanged. The response gains `receipt` and
  `receipt_status` (`recorded|disabled|failed|skipped`).
- Failure posture: starting fails closed on any log that does not verify (a torn final line, never
  acknowledged, is the one discarded exception); recording fails open to the caller and says so,
  unless `--strict-receipts`.
- Found by the live run, not the unit tests: `log_id` was derived from the raw device id and so put
  it in the file in the clear. Now `default_log_id` derives it from the HMAC.
- Verified live against the real CLI daemon, real OPA and a real signed pack with `integrity-cli`'s
  independent verifier: intact passes; a flipped decision is BAD_SIGNATURE; a removed tail is
  TRUNCATED; the wrong key is UNTRUSTED_SIGNER.
- Corrected stale text: `hook_runner` has spoken to this socket since integrity-core #166.
- Not done: BCC emitting the same receipts, shared conformance vectors, log rotation, anchoring
  (B4). Source review covers `shield/gate_receipts.py`, `shield/gate_daemon.py`,
  `shield/policy_engine/engine.py` and `shield/cli.py`.

## [2026-10-07] update | Gate receipts are strict by default

- A call whose receipt cannot be recorded is now **denied** in enforce mode by default
  (`strict_receipts=True` in `evaluate_pre_tool_use`, `GateServer` and `serve_forever`). Opt out
  with `shield gate-daemon --lenient-receipts`; `--strict-receipts` is removed because it is the
  default. Observe mode never blocks. Updated `concepts/guardrail-hooks.md`.
- Stated cost: a full disk or failing volume stops the gate answering `allow` until the receipt
  log is writable, so a strict gate trades availability for a complete record.
- Tests pin the default at the library signature, behaviourally, and at the CLI wiring
  (mutation-checked: inverting the CLI flag, or reverting either library default, fails a test).

## [2026-10-10] refactor | Gate receipts now use the SDK's shared writer

- `shield/gate_receipts.py` is a thin adapter over `integrity_sdk.core.receipt_writer` (integrity-core B2 stage 3), the
  same writer `bcc_middleware` uses, so the hardest-to-get-right code has one copy. Shield keeps its own vocabulary
  (`tool_name` + input digest bound into the action), its `shield-gate:` log id, and a flat single-log layout.
- No behavior change: a test pins the receipt hashes against the pre-swap writer from the same fixed key and inputs
  (receipts.jsonl and checkpoints.jsonl were also compared byte for byte when the swap was made), so existing logs keep
  verifying and extending. Strict-by-default is unchanged. Tests that injected failures via the deleted private
  `writer._receipts_fd` now use the SDK writer's `_current.receipts_fd`.
- Full suite: 627 passed, 17 skipped; 2 failures (`test_spool_enqueue_survives_an_unwritable_path...`,
  `test_from_environment_raises_on_unwritable_outbox`) are unrelated and fail identically on clean `main` (this sandbox runs
  as root, so "unwritable" paths are writable).

## [2026-10-11] fix | Policy results are interpreted by the shared decision vectors; two fail-opens closed

- Added `tests/test_decision_vectors.py`, which runs integrity-core's shared decision vectors (B2 stage 4) through
  `PolicyEngine.evaluate_with_basis`. It found that the engine read a result with `decision` but no `reason_code`, and any
  non-object result (string, list, number, boolean), as "no rule matched", so they took the event class default (`log_only` or
  `permit` for sensor events) instead of failing closed as the decision contract and BCC do.
- Fixed in `shield/policy_engine/engine.py`: any contract key present means a rule matched and goes to `resolve()` as it is
  (half-formed => `INTEGRITY_MALFORMED_DECISION`, deny); a non-object result goes to `resolve()` too. An object with none of the
  contract keys still means "no match" (Shield's entrypoint is the whole package object); two vectors record that as a pinned
  Shield exception.
- Behavior change: only for malformed policy output, which a verified pack should never produce. CI's integrity-core pin is
  bumped in this PR to a ref that carries the vector file.

## [2026-10-11] fix | Root-safe failure tests; guardrail-hooks TOC regenerated

- Three tests simulated "cannot write" with a `chmod`-ed directory, which does nothing for root: two failed as root and one
  passed without exercising the failure (`test_export_decision_still_returns_a_clean_failure_when_disk_is_also_full`). They
  now put a regular file where the directory must be, which fails for every user. Full suite: 680 passed, 17 skipped, 0 failed.
- Regenerated the stale TOC in `docs/wiki/concepts/guardrail-hooks.md` (`scripts/wiki_toc.py --check` now passes).

## [2026-10-11] feat | Advisory inference has a Settings form (integrity-core A7)

- New Settings tab **Advisory Inference** (`ui/src/components/InferenceSettings.jsx`, validator in `ui/src/inferenceSettings.js`): provider,
  failure mode, model, prompt profile, endpoint, `secret://` reference, timeout, max tokens, temperature and event classes. Shadow mode and
  strict redaction are displayed as fixed. Closes the gap recorded when the backend settings API landed (an operator could configure
  this only through the API, not the console).
- Verified: 4 Playwright tests (desktop and 390px, HTTP mocked at the control-plane boundary), a 390px screenshot reviewed by eye, `oxlint`
  clean on the new files, `vite build` passes. The sandbox has no downloadable browser, so the run used the preinstalled Chromium through a
  throwaway config outside the repo.

## [2026-10-11] docs | README and CLAUDE.md match the Advisory Inference tab

- `README.md` described a "Settings → Inference & Analysis panel" that did not exist (inference was configurable only through the API); it
  now names the real tab, what the form fixes and refuses, and what its tests cover. `CLAUDE.md`: test count (680 passed, 17 skipped), the
  `ui/` entry.

## [2026-10-11] fix | The console no longer blanks when /api/shield/agents omits `agents`; runtime-health e2e repaired

- Product bug found while repairing the spec: `Dashboard.jsx` assigned `agents.value.agents` straight into state, so a control plane that
  answered `{}` (or an older one without the field) crashed the whole console on `data.agents.flatMap` (blank page). It now defaults to `[]`.
- `ui/e2e/runtime-health.spec.ts` had been failing since the console's navigation was reorganised (Posture / Agent / Network / Decisions /
  Evidence / Configuration, Settings in the profile menu, Hermes profile on the Agent view) and, separately, because its decision times
  were fixed 2026-09-08 dates while the event stream shows only the last 24 hours. It now walks the current navigation and builds decision
  times relative to now. Verified: it passes, and fails again with the `Dashboard.jsx` change reverted.
- Still failing on clean `main`, not touched here: `e2e/opa-policies.spec.ts` (same stale-navigation drift) and the two `e2e/visual.spec.ts`
  screenshot comparisons (the sandbox renders differently from the committed baselines).

## [2026-10-11] fix | opa-policies e2e follows the reorganised console

- `ui/e2e/opa-policies.spec.ts` looked for a "Policy" button and an "OPA policies" tab that the console reorganisation removed; the OPA view now
  sits under Configuration. The spec opens Configuration, disambiguates the section heading from the view's own (they differ only by case), and
  scrolls the table into frame before its screenshot (it previously captured the top of the page, not the table). It fails when the mocked
  "differs from file" state is changed, so the three load states are really asserted. `e2e/visual.spec.ts` (sandbox-rendering diffs) is untouched.
## [2026-11-03] audit | Shield console visual contract

- Pages created: 0
- Pages updated: 0
- Dead links fixed: 0
- Orphans resolved: 0
- Stale pages refreshed: 0
- Aspirational content flagged: 0
- Added `docs/handoffs/2026-11-03-shield-ui-visual-audit.md` for the browser-verified UI audit;
  the wiki catalog did not need a new architecture page because this pass changed presentation
  geometry and test enforcement, not the Shield runtime model.

## [2026-11-03] docs | Advisory inference endpoint URL validation documented

- Updated the canonical advisory inference page, README, and specification for Shield PR #65:
  endpoint credentials, query parameters, and fragments are rejected by both UI and backend.
- Recorded backend and browser checks, including rejection before POST and desktop/mobile Settings
  coverage. Execution remains shadow-only with strict redaction.

## [2026-11-05] code | Protected-process interlock added to ActionBroker

- Added `shield/agent_core/protected_processes.py` and wired it into every actuator path in
  `action_broker.py` (fail-closed; exe-path identity; `resume` exempt). Updated
  `concepts/action-broker.md`.
- Tests: `tests/test_protected_processes.py` (fake-/proc, deterministic) plus a cgroup test fix
  (`cgroup.procs` now required). Full suite matches `main` on the 80 pre-existing failures/errors
  (no `opa` binary in the CI container); +16 passing.

## [2026-11-05] code | Commissioning-ladder instrumentation (outcome latency, shield resume, metrics endpoint)

- `EnforcementOutcome` gains `handle_to_contain_ms` and `resumes_event_id`; the router measures
  containment latency on a monotonic clock. New `shield resume` command and
  `GET /api/shield/commissioning-metrics`. Documented in `concepts/action-broker.md`.
- Found that `ActionBroker.resume` had no production caller, so a false-freeze rate was
  unmeasurable until now. Found that event timestamps are whole-second, so sensor-to-freeze
  latency is `[PLANNED]` and not reported.
- Tests: `tests/test_commissioning_instrumentation.py` (real subprocess, real signals, end-to-end
  against a real backend) and three in `tests/test_backend.py`. Suite matches `main`'s 80
  pre-existing failures/errors (no `opa` binary); +8 passing.

## [2026-11-05] code | Commissioning ladder view added to the cloud console

- New `ui/src/components/CommissioningView.jsx` (Governance > Commissioning) reading
  `/api/shield/commissioning-metrics`; formatting rule in `ui/src/commissioningFormat.js`.
  New page `concepts/commissioning-ladder.md`; index updated (15 -> 16 pages).
- Playwright: `ui/e2e/commissioning.spec.ts` (populated, empty-reads-Not-measured, error, device
  scope) and the route added to the design-system grammar sweep. All 35+ specs pass.
- Found the console already covers fleet/device detail (Agent workspace), evidence and
  receipt verification (Evidence), and conforms to the mock-matched tokens, so no duplicate views
  or restyle were added.

## [2026-11-05] code | Device app (Tauri) and the local outcome log

- New `device-app/`: `device-core` (plain Rust, tested), `src-tauri` thin shell (NOT compiled in the
  build sandbox, no webview libs), React UI with 8 Playwright specs. New page `concepts/device-app.md`.
- Shield now appends every enforcement outcome, with `pid`, to a local 0600 `outcomes.jsonl`
  (`shield/agent_core/outcome_log.py`), isolated from the backend sink by `fan_out`. `shield resume`
  writes its reversal there too. Updated `concepts/action-broker.md`.
- Cross-language contract: golden fixtures from the real Python writers, a Rust test that reads them,
  and `tests/test_device_contract.py` as the drift guard. A root `*.jsonl` ignore rule was hiding the
  fixtures; a narrow exception was added.
- Found by test: a visually-hidden label escaped the table's scroll clipping and caused 5px of
  page-level horizontal scroll at 390px; fixed by positioning the table.

## [2026-11-12] code | Gate zone mask and the sensor-silence fault

- New `shield/gate_zone.py`: an off-by-default zone mask on `shield gate-daemon` (`--zone-mode
  off|shadow|enforce`). It runs after the pack and can only turn a permit into a deny. Zones come
  from a pluggable provider; the shipped one is static. No AIS scorer is attached yet.
- New `shield/sensor_status.py`: `shield run --sensor-status-file` makes the watchdog write sensor
  health locally each tick, and the gate caps every zone while that status is stale, missing,
  unreadable or unhealthy.
- `DeviceConfig` gained `gate_zone`. Updated `concepts/guardrail-hooks.md`.

## [2026-11-13] code | Paid zone enforcement: signed entitlement, otherwise shadow

- New `shield/entitlement.py`, which signs and verifies `xibalba.shield.entitlement.v1`, plus an
  `EntitlementGate` that reloads the file when it changes and is checked on every decision.
- `ZoneMask.effective_mode()`: a requested `enforce` blocks only under a valid entitlement, and
  otherwise runs as `shadow`. `build_zone_mask` always attaches the gate. Receipts carry
  `ais_zone_entitlement:<status>`.
- New gate flags `--zone-entitlement-file` and `--zone-entitlement-key`, with config fields
  `gate_zone.entitlement_file` and `gate_zone.entitlement_keys`. Updated `concepts/guardrail-hooks.md`.

## [2026-11-13] code | Backend usage ledger for `shield usage-report`

- New `shield/backend/usage_ledger.py` and `POST /api/shield/usage`. A report is accepted only
  when its checkpoint verifies under the device's registered key, the counts sum to the range, and
  `tree_size == seq_to + 1`.
- Ledger `usage_reports`, keyed by `(tenant_id, log_id, seq_from)`. A replay is a no-op. A changed
  body or an overlapping range is a 409. Gaps are worked out when read.
- `GET /api/shield/usage` (admin) returns the month's totals per device, plus every log's gaps.
- Updated `concepts/guardrail-hooks.md`.

## [2026-11-13] code | Plans catalog, tenant plans, entitlement issuing and fetch

- New `shield/backend/plans.py` (`ShieldPlan` and an env-loaded catalog that fails closed) and
  `shield/backend/plans_store.py` (the `tenant_plans` table, where no row means free).
- New `shield/backend/entitlement_issuer.py`, which serves `GET /api/shield/entitlement` and signs with
  `SHIELD_ENTITLEMENT_SIGNING_KEY` through the existing `sign_entitlement`. With no key, nothing is
  issued. Enrollment pins the key as `gate_zone.entitlement_keys`.
- New `shield/entitlement_sync.py` and `shield entitlement-fetch`. The fetcher writes atomically, only
  verified documents replace the file, and the gate never imports the fetcher.
- Updated `concepts/guardrail-hooks.md`. Setting the new env vars on Render is an operator action.


## [2026-11-13] code | Stripe checkout, portal, webhook and seat sync (billing phase 3c)

- New `shield/backend/shield_billing.py`. Each paid plan is one subscription with two prices: a
  licensed per-device seat, and a metered overage backed by a Billing Meter. Both prices are checked
  against the plan catalog on every checkout, and a mismatch answers 503.
- Routes: `POST /api/shield/billing/{checkout,portal,sync}` and `GET /api/shield/billing` (admin).
  `POST /api/shield/stripe/webhook` reads the raw body before any JSON parsing, and the signature is
  its only authentication.
- The webhook is the only writer of `tenant_plans`. It re-reads the subscription from Stripe, so an
  event body never decides the plan. The event id and the plan are written in one transaction. On
  Render it forces a Supabase checkpoint and answers 503 if that fails, so Stripe redelivers.
- Trial: a tenant's first checkout gets 14 days (`SHIELD_STRIPE_TRIAL_DAYS`) with the card collected
  up front. There is one trial per tenant (`billing_customers.trial_used_at`).
- Enrollment syncs the seat count off the request thread, with prorations. Each change gets its own
  idempotency key from a `seat_syncs` row id, and phase 3d reads those rows for the period's device
  maximum.
- Design §9 now records the price suggestions and the trial decision. `render.yaml` declares the
  `SHIELD_STRIPE_*` keys, which the operator sets.

## [2026-11-13] code | Overage meter event at period close (billing phase 3d)

- `invoice.created` (subscription-cycle invoices only) closes a period. The handler re-reads the
  invoice and the subscription, computes `max(0, billable − seats × included_per_device)` from
  `usage_reports` received in the period and the period's maximum seat count, and sends a single meter
  event timestamped inside the period, while the invoice is still a draft.
- `meter_submissions` is the dedupe ledger. The row is written before the send, which fixes the value,
  and the Stripe event is marked processed together with the acknowledgement. A send unacknowledged
  for longer than Stripe's identifier window waits for operator reconciliation instead of being resent.
- The webhook now records Stripe-side seat changes into `seat_syncs`, so the history covers checkout
  and portal quantities too.
- Checkout also validates the meter and the overage price's per-1,000 `transform_quantity`.
- Limits: immediate cancellations and mid-period plan changes bill no overage (under-billing only). The
  portal must cancel at period end without plan switching, and the webhook endpoint must subscribe to
  `invoice.created`. Design §5 has the details.
