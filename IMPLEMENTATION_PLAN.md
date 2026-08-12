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
| INTEGRITY-LATEST protocol specs | DID, BCC, telemetry, AIS, Merkle anchoring, delegation, and evidence export semantics. |

## Audit checkpoint — 2026-08-06

Current observed status is [`docs/audits/2026-08-06-status.md`](docs/audits/2026-08-06-status.md). The root-free suite reports 103 tests passed and 7 skipped. The audit freshly verified a synthetic no-exporter CLI path and local Docker/dev-mode execution; historical README/HANDOFF evidence records process-exec and file-write eBPF verification, while TCP-connect still needs root live verification. `[x]` entries below mean the scoped artifact or test exists, not that live production exporter identity, eBPF overhead, or pilot readiness has been reverified.

## Known gap — 2026-08-12: BCC signing/submission path removed, not replaced

An uncommitted working-tree change (present since at least 2026-08-07, found while stabilizing
this repo ahead of a cross-repo rename pass) deleted `shield/integrity_exporter/` (the module
that called `integrity_sdk.bcc.build_bcc_commitment` and submitted signed decisions to
`bcc_middleware`'s `/v1/bcc/intercept`) and replaced it with unconditional OpenTelemetry spans
in `agent_core/router.py` via `integrity_sdk.telemetry.tracing.get_tracer()`. Verified directly,
not assumed: no file under `shield/` calls `build_bcc_commitment` anymore, and `bcc_middleware`
has no endpoint that ingests incoming OTel spans (its own OTel usage only wraps its *own*
`/v1/bcc/intercept` pipeline in a span, it does not receive spans from callers). **The net
effect: Shield currently has no path to a signed BCC commitment at all** — this is a real
regression from the "Closed" item below, not a planned-but-unbuilt gap. Tracked here per user
decision (2026-08-12) to continue other stabilization/rename work rather than redesign BCC
submission immediately. The open design question, when this is picked back up: should Shield
call `build_bcc_commitment` directly again (reverting the OTel direction), or should
`bcc_middleware` gain a real OTLP ingestion endpoint that converts incoming spans into signed
commitments (continuing the OTel direction)?

## Closed

- [x] Event schemas match Shield spec event classes.
- [x] Policy rule schema exists.
- [x] Policy Engine is table-driven, first-match, local/offline, and tested.
- [x] Agent Core exists: DeviceContext, AgentRegistry, EventRouter, EventLog.
- [~] Integrity Exporter uses real integrity-sdk BCC signing and telemetry submission. **Regressed
  2026-08-07 (uncommitted) — see "Known gap" above; not currently true.**
- [x] Exporter has historically documented live-stack proof against bcc_middleware with real verification token/batch index; current audit did not reproduce the live exporter path.
- [x] All six guardrail hooks exist and are tested.
- [x] CLI supports shield status, shield events, shield validate, and shield run.
- [x] Local JSON config loader and policy hot reload preserve last-known-good rules.
- [x] Dev sensor exists and is explicitly synthetic.
- [x] Linux process-exec eBPF sensor is live-verified.
- [x] Linux file-write eBPF sensor is live-verified.
- [x] Comprehensive SPECIFICATION.md exists in this repo.
- [x] Root-free test suite passes: 103 passed, 7 skipped.
- [x] Local policy bundles produce operator-visible policy version/hash in decisions.
- [x] File-write sensitive-path glob filtering is wired from device config.
- [x] Linux systemd service packaging and operator runbook exist.
- [x] Default SMB, professional-services, and regulated policy packs exist.
- [x] Root-free GitHub Actions CI exists.
- [x] `integrity-sdk` git dependency is pinned to a reviewed commit.
- [x] Signed policy bundle format is documented; local trusted-policy-hash enforcement exists.
- [x] Local decision logs include export status and CLI events output surfaces export failures.
- [x] Pilot acceptance metrics are defined.

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
- [ ] Re-run resource measurement with a registered DID and clean exporter queue.

### Policy Distribution And Updates

- [x] Design signed policy bundle format.
- [x] Add tenant policy distribution client: HTTP fetch, validation, trusted-hash enforcement, atomic replace.
- [ ] Specify safe code auto-update: signed downloads, staged rollout, rollback, and recovery.
- [x] Add operator-visible policy version/hash in local decisions and exported evidence.

### Documentation And CI Reconciliation

- [ ] Reconcile the INTEGRITY-LATEST protocol-facing Shield spec status so normative design and observed implementation are not conflated.
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

- [x] Integrate local Xibalba SLM inference engine (e.g. `llama.cpp`) for Tier 2 evaluation (MVP deployed via Qwen 0.5B).
- [x] Implement Action Broker to terminate suspicious processes using process group signals (`os.killpg`).
- [ ] Transition Action Broker from SIGKILL to cgroups/SIGSTOP for freezing processes during evaluation.
- [x] Implement Chain of Thought (CoT) structured JSON grammar to improve zero-shot Tier 2 accuracy.
- [x] Generate Supervised Fine-Tuning (SFT) dataset for Tier 2 model optimization.
- [ ] Define structured Agent-to-Agent (A2A) communication schema for local-to-cloud escalations.
- [ ] Implement Tier 3 Cloud Frontier fallback for ambiguous/low-confidence SLM decisions.
- [ ] Add cloud-fallback latency and decision metrics to burn-in reporting.

### Platform Expansion

- [ ] Windows ETW sensor.
- [ ] macOS endpoint sensor.
- [ ] Optional network appliance/container sensor for v2+.
- [x] Add baseline SIEM/SOAR JSONL and webhook exports.
- [ ] Add vendor-specific SIEM/SOAR field mappings and Integrity evidence links.

## Blocked

- [ ] TCP-connect sensor root verification is blocked by missing sudo/root in this environment.
- [ ] Windows/macOS sensors are blocked on access to target platforms for implementation and verification.
- [ ] Compliance reporting polish is blocked on INTEGRITY-LATEST evidence export maturity.
- [ ] Hosted tenant policy API service is outside this repo; client is implemented and tested with a real HTTP server.

- [ ] Current live eBPF/exporter re-verification is blocked until the audit environment has root capability and a live Integrity stack; `scripts/pilot_gate_report.py` records this as blocked until real artifacts are supplied.
- [ ] Real BCC signing/submission is blocked on a design decision — see "Known gap — 2026-08-12" above — before it can be re-verified or re-closed.

## Acceptance Criteria

- [ ] Linux process and file sensors are verified on pilot kernels.
- [ ] TCP-connect is either verified or explicitly removed from pilot claims.
- [x] shield run operates as a managed/supervised process.
- [ ] Policy validation and hot reload work under pilot conditions.
- [x] Local logs are inspectable and export failures are visible.
- [ ] Exporter uses a registered DID and produces queryable Integrity-backed evidence.
- [x] README, SPECIFICATION, SECURITY, and implementation docstrings agree on local tamper evidence versus OS-level hardening boundaries.

## Update Rule

Update this file with every status-table change, sensor verification change, exporter contract change, or pilot-readiness decision.
