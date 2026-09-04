# Xibalba Shield Production-Readiness Plan

**Status:** Active planning baseline; dashboard integration and one-host live TCP gate verified  
**Updated:** 2026-08-29  
**Target:** Linux-first production pilot, followed by hardened production release

## 1. Executive decision

Shield should be advanced as a **Linux-first agentic security control plane**. The near-term target is a production pilot on a defined kernel and distribution matrix, not a claim of complete EDR/XDR coverage or cross-platform endpoint protection.

The current implementation is close to a pilot in several areas: event schemas, local policy evaluation, agent guardrail hooks, ActionBroker containment, CLI operation, policy distribution, SIEM/SOAR output, and local tests. It is not yet production-ready because root-resistant operation, verified TCP enforcement, signed packaging and updates, durable evidence delivery, operational hardening, and adversarial validation remain incomplete.

Production readiness is an evidence threshold. A feature is not considered complete because code exists or a local simulation passes.

## 2. Readiness levels

### L0 — Research / pre-alpha (current baseline)

- Linux-first implementation with real and synthetic sensor boundaries.
- Local deterministic policy engine and agentic guardrail hooks.
- Integrity export path exists, but live Oracle/DID validation depends on funded external infrastructure.
- Root attacker, self-tamper, signed updater, and full TCP enforcement are unresolved.

### L1 — Controlled Linux pilot

Exit requires all of the following:

- A published supported OS/kernel matrix with native process, file, and TCP evidence on each target — see `docs/SUPPORTED_MATRIX.md`, the canonical record for this requirement.
- A production policy profile distinct from observe-only development defaults.
- Signed policy bundles with version pinning, atomic activation, rollback, and last-known-good recovery.
- Local enforcement that remains deterministic and available when OPA, the exporter, or the network is unavailable.
- Watchdog, service health, event-loss counters, queue backpressure, and operator-visible degraded states.
- Reproducible installation, upgrade, rollback, and uninstall procedures.
- Durable off-device evidence path with DID registration/readback and BCC/Oracle correlation where enabled.
- Resource burn-in and failure-injection results meeting the published pilot metrics.

### L2 — Hardened Linux production

L2 adds signed packages and releases, least-privilege service confinement, secure key storage and rotation, self-tamper detection/response, administrative RBAC, staged fleet rollout, incident response, upgrade safety, production observability, and independent adversarial review.

### L3 — Multi-platform and cloud-assisted expansion

Windows/macOS native sensors, enterprise deployment integration, and the planned cloud A2A/Tier 3 path are separate deliverables. They must not be represented as production coverage until validated on target operating systems and threat models.

## 3. Security invariants

These invariants govern design and acceptance:

1. Tier 1 deterministic policy is authoritative for enforcement. An LLM or cloud service may recommend or enrich a decision, but may not override a deterministic deny.
2. No hot-path network dependency exists for local enforcement.
3. Export failure never converts a local deny into an allow and never becomes proof of delivery.
4. Malformed, unsigned, expired, downgraded, or incompatible policy bundles are rejected as a whole; the last-known-good bundle remains active.
5. Every decision and containment action has a stable invocation/event correlation identifier, explicit policy version, and disclosed evidence state.
6. Sensor failure is visible and cannot be silently reported as full coverage.
7. Observe mode remains available for development and migration, but production control mode must be explicit and auditable.
8. “Tamper-evident” local logs are not described as root-resistant evidence. Root resistance requires a separate host and key-management design.

## 4. Workstreams

### A. Threat model and security architecture

Document trust boundaries and attack paths for a root attacker, a same-user attacker, a compromised agent/tool, a malicious policy publisher, a compromised model, replayed events, PID reuse, resource exhaustion, exporter outage, OPA outage, clock skew, and downgrade attempts. Record the residual risk and intended mitigation for every boundary.

**Deliverable:** signed security architecture decision record and threat-model test matrix.

### B. Deterministic enforcement plane

- Define explicit `observe`, `enforce`, and emergency-containment modes.
- Supervise OPA or provide a justified embedded/sidecar lifecycle design with health checks and bounded failure behavior.
- Implement signed policy bundle verification, expiry, monotonic version checks, rollback, and atomic reload.
- Add watchdog/self-health reporting and prevent stale “healthy” status after sensor or policy failure.
- Test malformed policy, unavailable OPA, exporter outage, full disk, clock skew, duplicate events, and restart recovery.

### C. Native Linux sensing

- Freeze the supported kernel/distribution matrix — done for scope (`docs/SUPPORTED_MATRIX.md`:
  Ubuntu 22.04/24.04/26.04 LTS); one of three rows has archived root-run evidence, two remain
  `not run`.
- Produce root-gated live evidence for process execution, file writes, and TCP connect decisions on every supported target.
- Replace conceptual sensor claims with measured coverage and event-loss telemetry.
- Define DNS as a separate scope decision; do not imply it is covered by TCP sensing.
- Test unload, attach failure, verifier rejection, buffer overflow, PID reuse, and high-event-rate behavior.

### D. Agentic security semantics

- Keep the six guardrail hooks typed, versioned, and fail-safe according to the declared product mode.
- Make application/framework adapters explicit: uninstrumented processes are not covered by opt-in hooks.
- Keep post-action verification labeled as detection rather than prevention.
- Establish a Tier 2 evaluation set with precision, recall, latency, abstention, and adversarial-prompt metrics.
- Defer Tier 3/cloud A2A implementation until the local deterministic path is stable and independently measurable.

### E. Containment and response

- Specify ActionBroker capabilities, privilege boundaries, timeouts, idempotency, and operator approval semantics.
- Validate process termination, cgroup isolation, network isolation, and recovery behavior under PID reuse and partial failure.
- Ensure every containment result distinguishes requested, attempted, completed, and verified states.

### F. Identity and evidence

- Complete DID registration/readback preflight and define credential/key custody, rotation, revocation, and loss recovery.
- Add a durable local export queue with bounded retention, retry policy, deduplication, replay protection, and explicit drop metrics.
- Correlate Shield event IDs with BCC/Oracle/OTLP records without claiming remote receipt when only local persistence exists.
- Define off-device retention, access control, clock requirements, and evidence verification procedures.

### G. Control plane and dashboard

- Replace development tokens/defaults with enrollment, tenant/device identity, RBAC, and auditable administration.
- Define policy publication, approval, staged rollout, canarying, rollback, and emergency revocation.
- Expose coverage, enforcement mode, sensor health, evidence backlog, policy version, exporter health, and containment outcomes in the dashboard.
- Ensure the dashboard distinguishes live backend data, local test data, synthetic attack simulation, and unavailable integrations.

### H. Packaging and operations

- Deliver signed packages/binaries, provenance metadata, SBOM, vulnerability scanning, reproducible build records, and release signatures.
- Harden systemd/service permissions and Linux capabilities; define the residual root-tamper limitation.
- Provide signed updater, rollback, migration, uninstall, and recovery procedures.
- Set and measure SLOs for startup, decision latency, event loss, CPU, memory, disk, export lag, and recovery time.
- Add structured logs, metrics, alerts, runbooks, and incident-response procedures.

### I. Verification and adversarial acceptance

Use layered evidence:

- Unit and contract tests for schemas, policy, hooks, exporter, configuration, and ActionBroker.
- Integration tests for OPA, local services, dashboard APIs, and evidence correlation.
- Root/kernel tests on real target hosts; skipped tests remain explicitly labeled.
- Chaos tests for service kill, sensor unload, network loss, disk exhaustion, key loss, policy rollback, and clock skew.
- Adversarial tests for prompt/tool abuse, policy bypass, replay, downgrade, event flooding, PID reuse, and containment failure.
- Multi-day burn-in with resource and event-loss measurements.

## 5. SaaS business readiness

Shield is a **Linux-first agentic security SaaS**, not just an on-prem sensor. The
technical gates above (L0-L2) are necessary but not sufficient for a sellable product;
this section names the business-layer gaps separately so they are not silently assumed
solved alongside the technical ones.

### 5.1 Tenancy and isolation

- `08eb97f` (fix/backend-admin-auth-and-ebpf-docs) introduced tenant-scoped admin
  tokens and closed the fail-open-on-missing-admin-token gap. That is the seed of
  multi-tenancy, not a completed tenant model: there is no cross-tenant data
  partitioning test, no verified isolation boundary between two tenants' event streams,
  policy bundles, or evidence exports, and no tenant lifecycle (provisioning,
  suspension, deletion with verified data purge).
- **Gap:** a real multi-tenant data model in the backend store plus adversarial
  cross-tenant leakage tests before any tenant is onboarded next to another.

### 5.2 Pricing tiers

The three existing policy packs (`policies/defaults/`: smb, professional-services,
regulated) are already a natural tier boundary — they differ in strictness and
compliance posture, not just label. Proposed mapping, not yet implemented as billing
logic:

| Tier | Policy pack | Readiness gate required |
|---|---|---|
| Starter | smb | Gate 2 (local enforcement) |
| Professional | professional-services | Gates 2-3 (+ sensor coverage) |
| Regulated | regulated | Gates 1-6 (adversarial validation required before sale) |

**Gap:** no tier is currently enforced anywhere in code — `shield local-run --profile`
selects a pack for a smoke run, not a billing-gated feature flag.

### 5.3 Billing and metering

No metering exists. A SaaS Shield needs per-tenant counters for at least: enrolled
device count, decision/event volume, containment actions taken, and evidence export
volume — none of these are currently aggregated or exposed outside `shield status`'s
single-tenant local summary. **Gap, not yet started.**

### 5.4 Support and SLA tiers

Tie support commitments to the technical readiness levels rather than inventing a
separate scale: L1 pilot = best-effort/community support, no uptime SLA; L2 hardened
production = contracted SLA (decision latency, evidence delivery lag, incident response
time) matching the SLOs already scoped in Workstream H. Do not offer a contracted SLA
before Gate 5 (packaging/operations) passes.

### 5.5 Onboarding

Self-serve onboarding requires signed package installation (Gate 5) and enrollment/
tenant identity (Workstream G) to exist first — there is currently no path for a new
tenant to install and register a device without direct engineering involvement.

## 6. Release gates

### Gate 1 — Scope and threat model

Pass when the supported matrix, trust boundaries, security invariants, residual risks, and explicit non-goals are approved and versioned.

### Gate 2 — Local enforcement

Pass when production control mode, signed policy lifecycle, watchdog behavior, offline operation, and failure semantics are tested on supported Linux targets.

### Gate 3 — Sensor coverage

Pass when process/file/TCP behavior has live evidence on every supported kernel, with measured event-loss and attach-failure behavior. DNS and other sensors remain separately marked.

### Gate 4 — Evidence continuity

Pass when local decisions, containment outcomes, exporter queue state, DID identity, and remote BCC/Oracle readback can be correlated and independently verified.

### Gate 5 — Packaging and operations

Pass when signed installation, upgrade, rollback, service confinement, key handling, observability, and recovery are exercised from a clean host.

### Gate 6 — Adversarial validation

Pass when the threat-model matrix has no unexplained critical bypasses and all known limitations are visible to operators.

### Gate 7 — Pilot burn-in

Pass when the selected pilot fleet meets resource, availability, event-loss, decision-latency, evidence-lag, and recovery SLOs for the agreed burn-in period.

## 7. Immediate implementation sequence

1. Add the explicit production policy profile and policy-bundle signing/rollback lifecycle.
2. Add supervisor/watchdog and health/degraded-state telemetry for OPA, sensors, exporter, and queue.
3. Complete live TCP verification on the selected Linux kernel matrix; record attach and event-loss evidence.
4. Make the exporter durable and complete DID registration/readback preflight tooling.
5. Harden systemd deployment and implement signed package/update/rollback mechanics.
6. Add failure-injection and adversarial tests, then run the pilot-gate report and burn-in.
7. Wire the dashboard to the resulting health, coverage, policy, evidence, and containment contracts.

Current evidence (2026-09-04): item 2 (watchdog/health telemetry) is implemented — a
`Watchdog` (`shield/watchdog.py`) now owns hot-reload checking, OPA restart-if-unhealthy,
an active OPA `/health` probe independent of evaluation traffic, and a status publish
covering policy/opa/sensors/exporter on its own timer, decoupled from the sensor event
loop that previously drove all of this only as a side effect of handled events. Sensor
`lost_events`/`last_event_at` (via BCC's `lost_cb`) and exporter `export_failures`/
`queue_depth` are new, real telemetry, not placeholders. `OpaSupervisor` is now wired
into the packaged systemd unit as an opt-in (`SHIELD_OPA_ARGS`, unset by default — the
unit still assumes an externally managed OPA sidecar unless an operator opts in). The
dashboard's `ShieldFleetOverview` no longer displays a frozen OPA/policy "healthy" value
past the exporter-status row's own staleness window. Not yet closed by this item: policy
bundle *signing*/version-pinning (item 1, separate), queue/backpressure telemetry beyond
the exporter's SDK-batcher queue depth (agent_core's router remains fully synchronous
with no queue of its own), and burn-in validation of the watchdog itself under sustained
load.

Current evidence (2026-08-29): the Shield dashboard has been validated in Chromium against the
real local Shield backend in both empty-tenant and seeded-tenant states. The populated state
renders enrolled devices, deny/contain counts, policy/exporter status, and the evidence graph
without uncaught browser errors. A live Linux host also passed the TCP-connect eBPF verifier and
the core BCC/Oracle/OPA stack reports `mode: enforce`, with OPA and chain reachability healthy.
This closes the dashboard wiring work and one-host TCP evidence item; it does not close the
kernel matrix, DID registration, remote BCC submission, packaging, or pilot burn-in gates.

Tier 3/cloud model routing is intentionally outside the critical path for the Linux pilot. It can be added after the local enforcement and evidence planes have production measurements.

## 8. External gates that cannot be completed locally

- Root and kernel-matrix validation on the actual target hosts.
- Windows/macOS native sensor implementation and validation.
- Reachable funded RPC/Oracle infrastructure for DID registration and audit readback.
- Production signing infrastructure, package repository, secrets/key custody, and release approvals.
- A controlled pilot fleet and multi-day operational burn-in.

Until these are supplied, the honest status is **pilot engineering complete/near-complete in local development, production deployment not yet proven**.

## 9. Definition of done for the first pilot

Shield may be called **Linux pilot-ready** only when Gates 1–5 pass, Gate 6 has no unresolved critical bypass, and Gate 7 has recorded results. The release notes must include the exact supported matrix, enabled sensors, enforcement mode, evidence limitations, root-tamper limitation, and rollback procedure.
