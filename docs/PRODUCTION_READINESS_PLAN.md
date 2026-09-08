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
- **Closed 2026-09-05:** signed policy bundle verification, expiry, monotonic version
  checks (pre-existing via `reject_downgrades`/`revision`), real operator-triggered
  rollback, and atomic reload (pre-existing swap-on-success pattern) are all now real.
  `shield/config/signing.py` reuses `integrity_sdk.did`'s Ed25519 primitives rather than
  a second signing scheme; `hot_reload.py` gained a bounded local history and
  independent expiry re-checking (an unchanged-but-now-expired bundle no longer stays
  silently "healthy" between file writes); three new `shield` subcommands
  (`sign-policy`, `policy-history`, `policy-rollback`) give an operator the actual
  workflow, not just the library primitives.
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

1. ~~Add the explicit production policy profile and policy-bundle signing/rollback
   lifecycle.~~ — **closed 2026-09-05**: the three production-tier profiles
   (`policies/defaults/{smb,professional-services,regulated}.json`, already distinct
   from observe-only dev defaults) predate this item; the genuinely missing half —
   cryptographic signing, expiry, and real operator-triggered rollback — is now built
   (`shield/config/signing.py`, `hot_reload.py`'s history/expiry/rollback, three new
   `shield` subcommands: `sign-policy`, `policy-history`, `policy-rollback`). Verified
   with a real generated keypair against real CLI runs: a validly-signed bundle loads
   and enforces with `require_signed_policy` set; a tampered bundle and an expired
   bundle are both rejected with a specific diagnostic, not a silent failure.
2. Add supervisor/watchdog and health/degraded-state telemetry for OPA, sensors, exporter, and queue.
3. Complete live TCP verification on the selected Linux kernel matrix; record attach and
   event-loss evidence. **Partially addressed 2026-09-05** — the parts doable without
   additional kernel hardware are closed: all three sensors now raise a typed
   `SensorAttachError` (stage-tagged: `bpf_load`/`kprobe`/`kretprobe`/`perf_buffer`) instead
   of a raw traceback on attach failure, the `lost_events` counter has a real test proving
   the BCC `lost_cb` wiring is load-bearing, and process-exec/file-write now have their own
   standalone root-run verify scripts matching TCP's (`scripts/verify_{process_exec,
   file_write}_root.py`), closing the script-parity gap `docs/SUPPORTED_MATRIX.md`'s closing
   procedure implicitly assumed. Real root-run evidence collected same day on kernel
   `7.0.0-30-generic`: all 11 relevant `tests/test_ebpf_sensor.py` cases pass (including the
   three new lost-events wiring tests), and all three `verify_*_root.py` scripts independently
   report `"status": "pass"`, archived at `artifacts/live-gate/{process-exec,file-write,
   tcp-connect}-root.log`. **Still open, and not closeable from this session**:
   `docs/SUPPORTED_MATRIX.md`'s Ubuntu 22.04 LTS and 26.04 LTS rows remain `⬜ not run` — this
   needs a real second/third kernel (VM or bare metal, not a shared-kernel chroot, per that
   doc's own closing procedure) actually provisioned and root-run against, which this
   environment cannot do.
4. Make the exporter durable and complete DID registration/readback preflight tooling.
   **Closed 2026-09-05.** Durable exporter: `IntegrityExporter.export_decision` previously
   did a single-shot synchronous BCC submission with no queue at all -- a failure during an
   outage lost the evidence immediately, not just eventually. `shield/integrity_exporter/
   spool.py` (new) mirrors `integrity-core/bcc_middleware/app/spool.py`'s design for
   consistency across both products: a single SQLite file, write-AFTER-failure (a successful
   submission never touches disk), capped exponential backoff on retry. `export_decision`
   now spools the already-built, already-signed commitment on failure;
   `IntegrityExporter.replay_pending()` drains it, called every `Watchdog.tick()` so an
   outage that stops new decisions doesn't also stop retrying what's already queued.
   `health()` now reports `spool_pending`/`spool_oldest_age_seconds` alongside the existing
   `export_failures`/`queue_depth`. 17 new/updated tests (`tests/test_exporter_spool.py`,
   updates to `tests/test_exporter_health.py`/`test_invocation_id.py`), all passing, real
   SQLite against `tmp_path`, only the network boundary mocked.

   DID registration/readback preflight: no such check existed before this -- the dashboard's
   demo-seed path (`shield/backend/api.py`) literally hardcoded `"did_registered": False` and
   `"oracle_readback": "blocked_until_rpc_credentials"` as synthetic placeholders (correctly
   labeled `"synthetic": True`, but no real alternative existed anywhere else in the repo).
   `shield/integrity_exporter/preflight.py` (new) and a new `shield preflight` CLI command
   give a real, checkable answer instead: does the local DID load/create cleanly, is
   `bcc_middleware` reachable (`GET /health`), and -- only if `--oracle-url` is configured --
   is the Oracle reachable (`GET /healthz`) and does it already know this DID
   (`GET /v1/agent/{did}`, treating 404 as a conclusive "not yet registered," not an error).
   Deliberately does NOT attempt full on-chain registration
   (`integrity_sdk.registration.register_agent`) -- that needs a funder key, RPC access, and
   deployed contract addresses this repo has no config surface for. 7 new tests
   (`tests/test_preflight.py` against a real local `http.server`, plus 2 CLI-wiring tests in
   `tests/test_cli.py`), all passing.
5. Harden systemd deployment and implement signed package/update/rollback mechanics.
   **Systemd hardening half addressed 2026-09-05, package signing/update/rollback still
   fully open.** `packaging/systemd/xibalba-shield.service` now runs as a dedicated
   `xibalba-shield` system account (not root, not the interactive dev/codex user) via
   `User=`/`Group=`, relying entirely on the three ambient eBPF capabilities for privilege
   rather than "whatever this account can already do"; `ProtectSystem=full`→`strict`;
   added `PrivateDevices`, `ProtectClock`, `ProtectHostname`, `ProtectProc=invisible`,
   `ProcSubset=pid`, `RestrictNamespaces`, `RestrictRealtime`, `SystemCallArchitectures=
   native`, `UMask=0077`. `scripts/install_linux_agent.sh` now creates that account and
   chowns config/log/state dirs to it (idempotent); `docs/runbooks/linux-agent.md` updated
   with the manual equivalent and a chown reminder for operator-created files. Deliberately
   did NOT add `SystemCallFilter=`/`MemoryDenyWriteExecute=` -- BCC's userspace LLVM JIT
   (used by `BPF(text=...)` before the real kernel-side bpf() load) makes it genuinely
   unclear whether either would silently break sensor attach, and guessing would violate
   this repo's own "no silent mocks" rule. `scripts/verify_hardened_unit.sh` (new) uses
   `systemd-run` to replicate every directive actually shipped and run all 3 sensors'
   `self_test()` under it -- root-only, not yet run in this session (this environment has
   no passwordless sudo); **an operator must run it and confirm PASS before trusting this
   hardening in production**, the same live-verification discipline item 3 used.

   Package signing/update/rollback mechanics: **mechanism built and tested 2026-09-06,
   not yet wired to the live install path.** New `shield/release/` package: `signing.py`
   (Ed25519 wheel signing/verification, reusing `shield/config/signing.py`'s PEM/0600
   key-handling convention but a deliberately SEPARATE key/trust domain from the
   policy-signing key) and `manager.py` (versioned `<releases-dir>/<version>/` +
   atomic-symlink-swap `current`, so rollback is a symlink flip with no reinstall, no
   network call, no re-verification). CLI surface: `scripts/sign_release.py`,
   `scripts/release_manager.py` (`install`/`rollback`/`list`). 18 new tests, including
   one that exercises the real venv+pip install path end to end (not just an injected
   fake installer) against a real trivial package -- all passing. Manually verified: a
   tampered wheel is correctly refused by `release_manager.py install` with a specific
   sha256-mismatch diagnostic, not a silent accept.

   **Deliberately NOT done in this pass**: `packaging/systemd/xibalba-shield.service`'s
   `ExecStart` still hardcodes `/usr/local/bin/shield`, not `<current-link>/bin/shield` --
   pointing the live unit at the versioned-release path is a separate, deliberate
   decision (it changes the real deployment path for every existing install) that
   shouldn't be bundled silently into the mechanism's introduction. `install_linux_agent.sh`
   also doesn't call the new tooling yet. `scripts/pilot_gate_report.py`'s
   `_installer_gate()` remains a self-attestation stub (checks a text file mentions
   certain keywords) -- it could now be pointed at a real attestation produced by
   `sign_release.py`/`verify_artifact`, but that wiring wasn't done here either.
6. Add failure-injection and adversarial tests, then run the pilot-gate report and burn-in.
   **Chaos/adversarial half closed 2026-09-05, burn-in run still open.** New
   `docs/design/threat-model-matrix-2026-09-06.md` maps all 14 scenarios workstream I
   names (7 chaos, 7 adversarial) to a real test, pre-existing coverage, or an honestly
   disclosed "not independently testable at this level" -- Gate 6's own required
   artifact, which didn't exist before. 12 of 14 have a real, passing automated test
   (`tests/test_chaos_adversarial.py`, 9 new tests); building it surfaced and fixed two
   real, previously-unknown bugs (not just confirmed already-correct behavior):
   `Watchdog.tick()` used to abort its entire status publish if any one sub-check raised
   (a dead sensor's own `health()` throwing meant the dashboard kept showing stale
   "healthy" data during exactly that failure -- now each sub-check is independently
   try/excepted), and `shield sign-policy` crashed with a raw `cryptography`-library
   traceback on a corrupted existing key file instead of a clean error. New
   `scripts/run_adversarial_tests.py` produces a real JSON artifact (not a self-
   attestation) and a new `_adversarial_gate()` in `scripts/pilot_gate_report.py`
   consumes it -- run end-to-end and verified passing. **Still fully open**: an actual
   48h+ burn-in run against a real pilot fleet (`scripts/burn_in.py` is a real harness,
   never run for the required duration against real hosts) -- that's a real multi-day
   operational exercise, not more code to write.
7. Wire the dashboard to the resulting health, coverage, policy, evidence, and containment
   contracts. **Partially addressed 2026-09-05.** Two real UI surfaces exist for Shield, and
   this closed the gap in the one this repo actually owns: `shield/backend/api.py`'s embedded
   `_console_html()` console (real, served directly by `shield-backend`, previously never
   called `/api/shield/exporter-status` at all) now has a "Device Health & Exporter Status"
   panel rendering real per-device `did_preflight` (item 4), `policy`/`sensors`/`exporter`
   watchdog telemetry (item 2), and the new `spool_pending`/`spool_oldest_age_seconds` (item
   4) -- falls back to the older demo-seed `did_registered`/`oracle_readback` fields when
   `did_preflight` is absent, so both real devices and the demo tenant render sensibly.
   Browser-verified end to end (real backend, real demo seed, then a real POST simulating a
   live device's watchdog payload) -- not just unit-tested. New regression coverage in
   `tests/test_backend.py`. **Also closed 2026-09-06**: a "Containment Outcomes" panel now
   calls `/api/shield/enforcement-outcomes` -- a real backend endpoint that existed since
   before this session but was never called from this console at all, so every containment
   attempt (including failures, like a `contain` decision whose target process had already
   exited) was invisible to an operator. Browser-verified with a real containment-failure
   outcome round-tripped through the real backend. `list_enforcement_outcomes`/
   `record_enforcement_outcome` had zero test coverage before this session; now covered in
   `tests/test_backend.py`. **What this still does NOT close**: coverage-matrix (item 3's
   per-kernel evidence) visualization and the 3D evidence graph's own containment-outcome
   nodes/edges (a separate, bigger visualization piece from the plain table added here)
   remain unbuilt in this console; and a
   *second*, unrelated UI surface -- `ShieldFleetOverview.tsx`/`ShieldPage.tsx` -- lives inside
   `integrity-core`'s own `integrity-dashboard`, not this repo, which is an architectural
   inconsistency with both repos' stated zero-cross-dependency boundary (`CLAUDE.md`). This
   repo's own `ui/` is still the untouched default Vite/React scaffold, never built out --
   tracked as a separate future item (build a real Shield-owned React app there, eventually
   migrating fleet-overview functionality out of `integrity-core`), not attempted in this
   pass since the embedded console was the faster, real win for this gate.

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
