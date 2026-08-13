# Xibalba Shield Implementation Plan

**Updated:** 2026-08-06
**Repository:** xibalba-shield
**Role:** Endpoint security agent for AI-agent discovery, local policy enforcement, guardrail hooks, and Integrity-backed evidence export.

This plan merges README.md, SPECIFICATION.md, SECURITY.md, archived HANDOFF.md, docs/audits/2026-08-06-status.md, eBPF verification notes, and current tests into a single task ledger.

## Specification Authority

| Source | Authority |
|---|---|
| SPECIFICATION.md | Normative Shield product and implementation specification. |
| README.md | Implementation status, verification evidence, commands, and plan. |
| docs/audits/2026-08-06-status.md | Current audit evidence, documentation drift findings, and production posture. |
| SECURITY.md | Implemented threat model, security posture, and limitations. |
| docs/archive/2026-08-06/HANDOFF.md | Historical operational handoff record. |
| shield/sensors/ebpf/README.md | eBPF verification and blocker record. |
| integrity-core protocol specs | DID, BCC, telemetry, AIS, Merkle anchoring, delegation, and evidence export semantics. |

## Audit checkpoint — 2026-08-06

Current observed status is [`docs/audits/2026-08-06-status.md`](docs/audits/2026-08-06-status.md). The root-free suite reports 103 tests passed and 7 skipped. The audit freshly verified a synthetic no-exporter CLI path and local Docker/dev-mode execution; historical README/HANDOFF evidence records process-exec and file-write eBPF verification, while TCP-connect still needs root live verification. `[x]` entries below mean the scoped artifact or test exists, not that live production exporter identity, eBPF overhead, or pilot readiness has been reverified.

## Closed gap — 2026-08-12: BCC signing/submission path restored

A 2026-08-07 uncommitted working-tree change had deleted `shield/integrity_exporter/` (the
module that called `integrity_sdk.bcc.build_bcc_commitment` and submitted signed decisions to
`bcc_middleware`'s `/v1/bcc/intercept`) and replaced it with unconditional OpenTelemetry spans
in `agent_core/router.py`, leaving Shield with no path to a signed BCC commitment at all — a real
regression, first documented here the same day it was found (2026-08-12), then resolved the same
day. Resolution: restored `shield/integrity_exporter/` from git history (`f86c0f0^`), re-added an
optional `exporter` param to `EventRouter.__init__`, and wired the previously-dead
`--bcc-middleware-url`/`--oracle-url`/`--agent-label`/`--no-exporter` CLI flags in `cli.py`'s
`run` subcommand to construct it. The OTel span and the Integrity Exporter now run as two
independent, separately best-effort export paths in `router.py`'s `handle()` — restoring the
exporter did not remove the OTel span, matching the ecosystem's prior resolution of this same
fork (`integrity-core/PRODUCTION_GAPS.md` §15). One deliberate deviation from the pre-deletion
version: `IntegrityExporter` now constructs its `IntegrityClient` with `background_flush=True`
(the SDK's own default) instead of the original `background_flush=False`, since Shield's
decisions fire on a real-time enforcement path that must not block on a synchronous telemetry
flush to a possibly slow or unreachable `bcc_middleware`.

## Closed

- [x] Event schemas match Shield spec event classes.
- [x] Policy rule schema exists.
- [x] Policy Engine is table-driven, first-match, local/offline, and tested.
- [x] Agent Core exists: DeviceContext, AgentRegistry, EventRouter, EventLog.
- [x] Integrity Exporter uses real integrity-sdk BCC signing and telemetry submission. Regressed
  2026-08-07, restored 2026-08-12 — see "Closed gap" above.
- [x] Exporter has historically documented live-stack proof against bcc_middleware with real verification token/batch index; current audit did not reproduce the live exporter path.
- [x] All six guardrail hooks exist and are tested.
- [x] CLI supports shield status, shield events, shield validate, and shield run.
- [x] Local JSON config loader and policy hot reload preserve last-known-good rules.
- [x] Dev sensor exists and is explicitly synthetic.
- [x] Linux process-exec eBPF sensor is live-verified.
- [x] Linux file-write eBPF sensor is live-verified.
- [x] Comprehensive SPECIFICATION.md exists in this repo.
- [x] Root-free test suite passes: 118 passed, 9 skipped (2026-08-12; was 103/7 before the
      ActionBroker-wiring tests landed).
- [x] Local policy bundles produce operator-visible policy version/hash in decisions.
- [x] File-write sensitive-path glob filtering is wired from device config.
- [x] Linux systemd service packaging and operator runbook exist.
- [x] Default SMB, professional-services, and regulated policy packs exist.
- [x] Root-free GitHub Actions CI exists.
- [x] `integrity-sdk` git dependency is pinned to a reviewed commit.
- [x] Signed policy bundle format is documented; local trusted-policy-hash enforcement exists.
- [x] Local decision logs include export status and CLI events output surfaces export failures.
- [x] Pilot acceptance metrics are defined.
- [x] `shield run` actually enforces `contain` decisions via `agent_core/action_broker.py`'s
  real OS-signal containment (SIGSTOP), not just logging/exporting them. Added 2026-08-12:
  previously `ActionBroker` existed and was tested in isolation, but nothing in the live
  code path — not even the guardrail hooks — ever called it, so `contain` decisions had no
  real-world effect. `EventRouter` now takes an optional `action_broker` param and calls
  `action_broker.contain(pid)` (freeze-only, no timeout) as the very first step in
  `handle()`, before any network call, for process-related events. `shield run` constructs
  a real `ActionBroker` by default; `--no-containment` opts out (observe/log/export only).
  Verified against a real spawned process (`sleep 30`): went from `R (running)` to
  `T (stopped)` via genuine SIGSTOP through the full router pipeline, then resumed cleanly.

## Planned And Todo

### Shield Platform MVP

Goal: demonstrate Xibalba Shield as a real tenant security platform under the Xibalba Shield page, backed by the endpoint agent in this repository and Integrity evidence.

- [x] Create a Shield backend service with tenant/device APIs.
- [x] Add device enrollment API: issue device config, tenant ID, policy URL, and expected agent label.
- [x] Add policy distribution API compatible with the existing `tenant_policy_url` client.
- [x] Add decision ingestion API for dashboard/demo visibility without weakening local enforcement.
- [x] Add burn-in metrics ingestion API for CPU/RAM/event-rate/export-health snapshots.
- [x] Add exporter registration status API backed by `scripts/verify_oracle_registration.py` output or equivalent backend readback.
- [x] Add SIEM/SOAR destination configuration API for JSONL/webhook/vendor-specific adapters.
- [x] Add tenant isolation tests for backend device-token ingestion paths.
- [x] Add backend persistence schema for tenants, devices, policies, decisions, metrics, integrations, and enrollment tokens.
- [x] Add demo seed data and scripted event generator for repeatable MVP demos.
- [x] Build the Xibalba Shield page as an operational console, not a marketing page.
- [x] Dashboard view: device inventory, online/offline state, active policy hash/version, export health.
- [x] Decision stream view: allow/deny/contain/escalate events with device/event/rule/severity/export fields.
- [x] Policy view baseline: policy hash/version is surfaced in device inventory; full editor/rollout workflow remains planned.
- [x] Evidence view baseline: DID/exporter status is stored and shown in dashboard summary; Integrity audit links remain blocked on evidence reporting surface.
- [x] Burn-in view: event rate, CPU/RAM, deny/escalate volume, export reliability, false-positive review placeholders.
- [x] Demo controls: seed synthetic shadow-agent, sensitive-write, PHI-context, network, exporter-status, metrics, and SIEM config scenarios with clear demo labeling.
- [ ] Add full policy editor, staged rollout controls, and richer dashboard filters.
- [x] Add typed detection-quality metric ingestion for Shield ADR, blocking false-positive rate,
  precision, mean time to contain, label source, and Integrity receipt/readback status.
- [x] Add Integrity-backed detection-quality reports that reproduce Shield ADR from signed
  decisions and labels rather than local counters alone.

MVP rule: the backend and page may display synthetic demo events only when they are labeled synthetic. Customer-facing claims must be based on real agent runs, real policy evaluation, and real export/readback status.

### Linux Sensor Completion

- [x] Reduce TCP-connect BCC header blocker with BTF-checked struct-prefix source.
- [ ] Run root live verification for TCP-connect on target kernel.
- [ ] Design DNS observation separately via uprobe or packet parsing.
- [x] Add config-loadable sensitive-path filtering for file events.
- [ ] Measure resource budget with verified real sensors running, not only dev/exporter paths.

### Integrity Evidence Closure

- [ ] Register the Shield exporter DID with Integrity Oracle.
- [x] Add explicit DID registration readback script.
- [ ] Execute DID readback against live funded RPC/oracle environment.
- [ ] Verify exported Shield decisions are visible through the intended evidence/audit surface.
- [x] Verify Shield ADR and companion detection-quality metrics are reproducible through the
  intended Integrity evidence/audit surface. Closed locally with a 2026-08-13 live smoke:
  BCC `/v1/bcc/verify_token` and Oracle `/v1/audit-log` both confirmed the ADR-counted sample.
- [ ] Re-run resource measurement with a registered DID and clean exporter queue.

### Policy Distribution And Updates

- [x] Design signed policy bundle format.
- [x] Add tenant policy distribution client: HTTP fetch, validation, trusted-hash enforcement, atomic replace.
- [ ] Specify safe code auto-update: signed downloads, staged rollout, rollback, and recovery.
- [x] Add operator-visible policy version/hash in local decisions and exported evidence.

### Documentation And CI Reconciliation

- [ ] Reconcile the integrity-core protocol-facing Shield spec status so normative design and observed implementation are not conflated.
- [x] Resolve the specification wording inconsistency between five and six guardrail hooks in repo-local SPECIFICATION/README; six hook points are authoritative.
- [x] Update stale README, archived HANDOFF, sensor-base, CLAUDE, and generated package metadata counts/status text; no tracked egg-info metadata remains.
- [x] Pin the `integrity-sdk` dependency to a reviewed release or commit.
- [x] Add free GitHub Actions CI for root-free tests and explicit root-gated skip reporting.

### Pilot Readiness

- [x] Package Linux agent as a managed service or supervised process.
- [x] Add install, uninstall, rollback, and diagnostic runbooks.
- [x] Add Linux install and policy update helper scripts.
- [x] Create default policy packs for SMB, professional services, and regulated environments.
- [x] Define pilot acceptance metrics: resource use, false positives, export success, operator usability.
- [x] Add root-free burn-in harness for throughput/RSS/decision mix snapshots.
- [x] Add aggregate pilot gate report for external verification artifacts.

### Hybrid Cascading Architecture (A2A)

Corrected 2026-08-12: the items below were marked `[x]` in a way that overstated integration.
`slm_training/` is real, running code, but it is a **standalone demo** — nothing under `shield/`
imports `llama_cpp`, `qwen`, or `slm_training` (confirmed by grep), and `slm_training/app.py`
does its own `os.killpg(..., SIGKILL)` containment directly against the eBPF sensor, bypassing
`agent_core/action_broker.py`'s real `ActionBroker` (SIGSTOP/SIGCONT/cgroup-freeze) entirely. As
of this session, `shield/agent_core/slm_backend.py` provides the actual enforcement-path
integration point: an `SlmBackend` protocol, a `SimulatedSlmBackend` (deterministic, explicitly
labeled synthetic), and a `LocalSlmBackend` (thin wrapper around the Qwen demo's inference, not
its containment logic — decisions still route through the real `ActionBroker`), wireable via
`shield run --slm-backend {none,simulated,local}` (default `none`, unchanged behavior).

- [~] Local Xibalba SLM inference engine exists and runs (`slm_training/app.py`, `llama.cpp`
      via `llama-cpp-python`, MVP model Qwen2.5-0.5B-Instruct-Q4_K_M) — **not yet wired** into
      `shield/`'s enforcement path as this repo's own Tier-2 authority; `LocalSlmBackend`
      (`shield/agent_core/slm_backend.py`) now provides that wiring for inference, still routing
      containment through the real `ActionBroker`, not the demo's own SIGKILL path.
- [x] Real OS-level `ActionBroker` (SIGSTOP/SIGCONT, cgroup v2 freeze, SIGKILL only from an
      explicit timeout escalation) exists and is wired into `shield run`'s live loop as of
      2026-08-12 — see `agent_core/action_broker.py` and the "Closed gap — 2026-08-12" entry
      above. The demo's separate `os.killpg`-based containment in `slm_training/app.py` is not
      this and is not used by `shield run`.
- [~] Chain of Thought (CoT) structured JSON grammar exists and works
      (`slm_training/app.py`'s `response_format` JSON-schema-constrained generation) but only
      inside the standalone demo — real, not a placeholder, just not yet the production Tier-2
      path.
- [~] A Supervised Fine-Tuning (SFT) dataset generator exists
      (`slm_training/generate_dataset.py`, ~950 templated rows from 10 malicious/8 benign
      command patterns), but it's small and template-based, not the "1,000+ examples, production-
      ready" bar `slm_training/README.md` itself names. `slm_training/train.py`'s QLoRA fine-tune
      script is documented as unrunnable on this machine (needs an NVIDIA GPU) — no evidence a
      fine-tune has actually been run. **Scaling this (more diverse synthetic data, GPU/inference
      compute to actually run training) is an open community contribution area** — see README's
      "Community: help build Tier 2" section.
- [ ] Two different base models are referenced inconsistently: `models/Llama-3.2-1B-Instruct-
      Q4_K_M.gguf` (named in `slm_training/README.md`'s narrative) vs. the model actually wired
      into `slm_training/app.py` (Qwen2.5-0.5B). Resolve which is canonical before further Tier-2
      work — not resolved this session, flagged rather than silently picked.
- [ ] Define structured Agent-to-Agent (A2A) communication schema for local-to-cloud escalations.
- [ ] Implement Tier 3 Cloud Frontier fallback for ambiguous/low-confidence SLM decisions.
- [ ] Add cloud-fallback latency and decision metrics to burn-in reporting.
- [x] Add detection-quality metrics to burn-in reporting: Shield ADR, precision, blocking
  false-positive rate, mean time to contain, and label provenance.

### Platform Expansion

- [ ] Windows ETW sensor.
- [ ] macOS endpoint sensor.
- [ ] Optional network appliance/container sensor for v2+.
- [x] Add baseline SIEM/SOAR JSONL and webhook exports.
- [ ] Add vendor-specific SIEM/SOAR field mappings and Integrity evidence links.

## Blocked

- [ ] TCP-connect sensor root verification is blocked by missing sudo/root in this environment.
- [ ] Windows/macOS sensors are blocked on access to target platforms for implementation and verification.
- [ ] Compliance reporting polish is blocked on integrity-core evidence export maturity.
- [x] Detection-quality reporting is no longer blocked on Shield-side live Integrity readback:
  the backend report verifies BCC tokens and optional Oracle audit-log rows. Full oracle-signed
  evidence export remains an `integrity-core` Phase C concern, not a Shield backend blocker.
- [ ] Hosted tenant policy API service is outside this repo; client is implemented and tested with a real HTTP server.

- [ ] Current live eBPF/exporter re-verification is blocked until the audit environment has root capability and a live Integrity stack; `scripts/pilot_gate_report.py` records this as blocked until real artifacts are supplied.
- [ ] Real BCC signing/submission is restored (see "Closed gap — 2026-08-12" above) but not yet
  live-verified against a running `bcc_middleware` in this environment — same root cause as the
  eBPF re-verification item above (needs a live stack, not blocked on a design decision anymore).

## Acceptance Criteria

- [ ] Linux process and file sensors are verified on pilot kernels.
- [ ] TCP-connect is either verified or explicitly removed from pilot claims.
- [x] shield run operates as a managed/supervised process.
- [x] `contain` decisions produce real OS-level containment (SIGSTOP via ActionBroker), not
  only a logged/exported decision — see "Closed" above.
- [ ] Policy validation and hot reload work under pilot conditions.
- [x] Local logs are inspectable and export failures are visible.
- [ ] Exporter uses a registered DID and produces queryable Integrity-backed evidence.
- [x] README, SPECIFICATION, SECURITY, and implementation docstrings agree on local tamper evidence versus OS-level hardening boundaries.

## Known open items — not closed this session (2026-08-12)

Real gaps, honestly listed as open rather than implied closed. Each is either not this
repository's decision to make, or needs a resource this session doesn't have:

- **`INTEGRITY_CORE_PAT` GitHub secret does not exist, and may no longer even be needed.** It was
  meant for `integrity-dashboard`'s wiki-sync workflow to check out `integrity-core` as a private
  sibling repo — but `integrity-dashboard` now lives *inside* `integrity-core` (folded in during
  an earlier session), and that workflow (`integrity-dashboard/.github/workflows/wiki-sync.yml`)
  still does a redundant second checkout of `integrity-core` from within `integrity-core` itself.
  Removing that redundant checkout (reading `docs/wiki/` from the already-checked-out repo
  instead) would likely eliminate the need for this secret entirely — an `integrity-core`-side
  fix, out of scope for this repo, not evaluated further this session. Unrelated to this repo's
  own `sync-wiki.yml`, which only ever needed the default `GITHUB_TOKEN`.
- **`audit/harness-loop-2026-07-30` (in `integrity-core`) is not landed into `main`.** A timing
  decision for the user, not a code gap.
- **ZK verifier test coverage in `integrity-core`** (`UltraPlonkVerifier.sol` has zero tests
  exercising it with a real proof) — a different repository's gap, tracked there.
- **Windows/macOS native sensors** — interface-boundary stubs only; needs those target platforms
  to implement and verify against.
- **Root-gated eBPF test coverage (TCP-connect)** — needs root on the target kernel to verify;
  cannot be closed from this environment.
- **GitHub Actions "Read and write permissions" for the new `sync-wiki.yml` workflow** — a repo
  Settings toggle needed for the default `GITHUB_TOKEN` to push to the wiki repo; the user needs
  to confirm this is set for both `xibalba-shield` and `xibalba-cortex` (see `.github/workflows/
  sync-wiki.yml`'s own comment for the exact setting).
- **OPA sidecar and Rego policy completeness** (§7.0 of `SPECIFICATION.md`) — `professional-
  services.json` and `regulated.json` have no Rego translation yet, and nothing automatically
  starts the OPA server `shield run` depends on. Real, open, not silently worked around.
- **Tier-2 SLM training compute** — no fine-tune has been run (`slm_training/train.py` needs an
  NVIDIA GPU this environment doesn't have); this is the explicit community-contribution ask in
  README.md's "Community: help build Tier 2" section, not a solo TODO.

## Update Rule

Update this file with every status-table change, sensor verification change, exporter contract change, or pilot-readiness decision.
