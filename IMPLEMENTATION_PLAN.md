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

Current observed status is [`docs/audits/2026-08-06-status.md`](docs/audits/2026-08-06-status.md). The root-free suite reports 66 tests passed and 7 skipped. The audit freshly verified a synthetic no-exporter CLI path and local Docker/dev-mode execution; historical README/HANDOFF evidence records process-exec and file-write eBPF verification, while TCP-connect remains blocked. `[x]` entries below mean the scoped artifact or test exists, not that live production exporter identity, eBPF overhead, or pilot readiness has been reverified.

## Closed

- [x] Event schemas match Shield spec event classes.
- [x] Policy rule schema exists.
- [x] Policy Engine is table-driven, first-match, local/offline, and tested.
- [x] Agent Core exists: DeviceContext, AgentRegistry, EventRouter, EventLog.
- [x] Integrity Exporter uses real integrity-sdk BCC signing and telemetry submission.
- [x] Exporter has historically documented live-stack proof against bcc_middleware with real verification token/batch index; current audit did not reproduce the live exporter path.
- [x] All six guardrail hooks exist and are tested.
- [x] CLI supports shield status, shield events, shield validate, and shield run.
- [x] Local JSON config loader and policy hot reload preserve last-known-good rules.
- [x] Dev sensor exists and is explicitly synthetic.
- [x] Linux process-exec eBPF sensor is live-verified.
- [x] Linux file-write eBPF sensor is live-verified.
- [x] Comprehensive SPECIFICATION.md exists in this repo.
- [x] Root-free test suite passes: 66 passed, 7 skipped.
- [x] Local policy bundles produce operator-visible policy version/hash in decisions.
- [x] File-write sensitive-path glob filtering is wired from device config.
- [x] Linux systemd service packaging and operator runbook exist.
- [x] Default SMB, professional-services, and regulated policy packs exist.
- [x] Root-free GitHub Actions CI exists.
- [x] `integrity-sdk` git dependency is pinned to a reviewed commit.
- [x] Signed policy bundle format is documented; local trusted-policy-hash enforcement exists.

## Planned And Todo

### Linux Sensor Completion

- [ ] Unblock TCP-connect eBPF verification by upgrading BCC or using verified BTF-based struct handling.
- [ ] Design DNS observation separately via uprobe or packet parsing.
- [x] Add config-loadable sensitive-path filtering for file events.
- [ ] Measure resource budget with verified real sensors running, not only dev/exporter paths.

### Integrity Evidence Closure

- [ ] Register the Shield exporter DID with Integrity Oracle.
- [ ] Verify GET /v1/agent/{did} or equivalent readback for Shield exporter identity.
- [ ] Verify exported Shield decisions are visible through the intended evidence/audit surface.
- [ ] Re-run resource measurement with a registered DID and clean exporter queue.

### Policy Distribution And Updates

- [x] Design signed policy bundle format.
- [ ] Add tenant cloud policy client only after a real server contract exists.
- [ ] Specify safe code auto-update: signed downloads, staged rollout, rollback, and recovery.
- [x] Add operator-visible policy version/hash in local decisions and exported evidence.

### Documentation And CI Reconciliation

- [ ] Reconcile the INTEGRITY-LATEST protocol-facing Shield spec status so normative design and observed implementation are not conflated.
- [x] Resolve the specification wording inconsistency between five and six guardrail hooks in repo-local SPECIFICATION/README; six hook points are authoritative.
- [ ] Update stale README, archived HANDOFF, sensor-base, CLAUDE, and generated package metadata counts/status text.
- [x] Pin the `integrity-sdk` dependency to a reviewed release or commit.
- [x] Add free GitHub Actions CI for root-free tests and explicit root-gated skip reporting.

### Pilot Readiness

- [x] Package Linux agent as a managed service or supervised process.
- [x] Add install, uninstall, rollback, and diagnostic runbooks.
- [x] Create default policy packs for SMB, professional services, and regulated environments.
- [ ] Define pilot acceptance metrics: resource use, false positives, export success, operator usability.

### Platform Expansion

- [ ] Windows ETW sensor.
- [ ] macOS endpoint sensor.
- [ ] Optional network appliance/container sensor for v2+.
- [ ] SIEM/SOAR export integrations through Integrity evidence paths.

## Blocked

- [ ] TCP-connect sensor is blocked by current BCC/kernel version skew.
- [ ] Windows/macOS sensors are blocked on access to target platforms for implementation and verification.
- [ ] Compliance reporting polish is blocked on INTEGRITY-LATEST evidence export maturity.
- [ ] Tenant cloud policy API is blocked until server contract exists.

- [ ] Current live eBPF/exporter re-verification is blocked until the audit environment has root capability and a live Integrity stack.

## Acceptance Criteria

- [ ] Linux process and file sensors are verified on pilot kernels.
- [ ] TCP-connect is either verified or explicitly removed from pilot claims.
- [x] shield run operates as a managed/supervised process.
- [ ] Policy validation and hot reload work under pilot conditions.
- [ ] Local logs are inspectable and export failures are visible.
- [ ] Exporter uses a registered DID and produces queryable Integrity-backed evidence.
- [ ] README, SPECIFICATION, SECURITY, and implementation docstrings agree.

## Update Rule

Update this file with every status-table change, sensor verification change, exporter contract change, or pilot-readiness decision.
