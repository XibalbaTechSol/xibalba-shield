# Xibalba Shield Specification

**Version:** 1.0 implementation specification
**Status:** normative for the xibalba-shield repository
**Updated:** 2026-08-06
**Owner:** Xibalba Solutions

Xibalba Shield is an endpoint security agent for discovering AI agents and tools, constraining risky behavior, and exporting verifiable evidence into Integrity Protocol. Shield is the endpoint sensor and local enforcer. Integrity Protocol is the identity, BCC, telemetry, scoring, and evidence substrate. Shield consumes Integrity; it does not duplicate it.

This specification defines what Shield must do, how the current repository is organized, which interfaces are stable, and which gaps remain. The implementation status ledger remains [README.md](README.md); this document defines the target behavior and module contracts.

## Current audit and implementation boundary

The current audit status is [`docs/audits/2026-08-06-status.md`](docs/audits/2026-08-06-status.md). The root-free suite reports 66 tests passed and 7 skipped. Historical repository evidence records Linux process-exec and file-write eBPF verification; the audit did not reproduce live eBPF/exporter verification and TCP-connect remains blocked. This specification is normative for behavior, but README, IMPLEMENTATION_PLAN, SECURITY, and the audit ledger determine observed implementation status.

## 1. Source Of Truth And Scope

### 1.1 Normative Documents

| Document | Authority |
|---|---|
| [SPECIFICATION.md](SPECIFICATION.md) | Shield product behavior, module contracts, event semantics, local enforcement model, and roadmap scope. |
| [README.md](README.md) | Current implementation status, verification evidence, commands, and plan. |
| [SECURITY.md](SECURITY.md) | Implemented security posture, threat model, disclosure handling, and current limitations. |
| [shield/sensors/ebpf/README.md](shield/sensors/ebpf/README.md) | Linux eBPF verification record and TCP-connect blocker details. |
| INTEGRITY-LATEST spec/integrity-protocol-v0.4.md | Protocol primitives consumed by Shield: DID, BCC, telemetry, AIS, Merkle anchoring, delegation, and evidence exports. |
| INTEGRITY-LATEST spec/xibalba-shield-v1.md | Protocol-facing companion boundary for Shield. |

### 1.2 Product Scope

Shield v1 is:

- An endpoint agent for AI-agent discovery and policy enforcement.
- A local policy decision engine that can operate without a cloud round trip.
- A producer of signed evidence for Integrity Protocol.
- A guardrail hook library for semantic agent/LLM boundaries.
- A Linux-first security agent with verified process and file-write sensing, and a blocked TCP-connect sensor pending BCC/kernel compatibility work.

Shield v1 is not:

- A reputation backend or AIS scoring engine.
- A Merkle anchoring service.
- A full EDR/XDR replacement.
- A content-inspection or DLP system.
- A payment rail, custodial key service, or settlement system.
- A HIPAA healthcare product; Integrity Health is the healthcare vertical.

## 2. System Relationship

### 2.1 Dependency Direction

The dependency graph is one-way: xibalba-shield depends on INTEGRITY-LATEST public interfaces. INTEGRITY-LATEST must never import Shield code or rely on Shield for correctness. A Shield sensor failure must not alter AIS computation, BCC canonicalization, Merkle batching, chain schemas, or protocol anchoring.

### 2.2 Evidence Flow

1. Sensor or guardrail hook observes an event.
2. Agent Core normalizes the event and attaches device/agent context.
3. Policy Engine evaluates ordered rules.
4. Event Router records a local PolicyDecision.
5. Integrity Exporter signs a BCC commitment using integrity-sdk.
6. The commitment and telemetry are submitted to INTEGRITY-LATEST services.
7. Integrity services score, anchor, and expose evidence through their own surfaces.

### 2.3 Enforcement Boundary

Shield enforcement is local. Integrity evidence is remote and verifiable. If export fails, local enforcement still happens and local decision logging still records the outcome. Export failure must be visible, retried when possible, and never silently converted into proof.

## 3. Architecture

### 3.1 Runtime Model

Shield v1 runs as one lightweight endpoint process composed of internal modules rather than a mesh of local services. Runtime modules:

- shield.sensors: OS and synthetic event sources.
- shield.agent_core: registry, router, device context, event log.
- shield.policy_engine: ordered rule evaluation.
- shield.guardrail_hooks: semantic agent/LLM boundary gates.
- shield.integrity_exporter: BCC signing and telemetry submission.
- shield.config: local config loading and policy hot reload.
- shield.cli: operator commands and executable agent loop.

### 3.2 Resource Budget

| Resource | Budget |
|---|---:|
| Resident memory | <= 90 MB |
| Sustained CPU | <= 3-5% on a typical endpoint |
| Hot-path network dependence | none for enforcement |
| Local persistence | append-only JSONL decision log plus minimal DID/key material |

### 3.3 Failure Philosophy

- Local policy enforcement must continue without cloud access.
- Export failures must not reverse an already-made local decision.
- Guardrail exceptions must be logged and surfaced; they must not be hidden as successful policy evaluation.
- Malformed policy bundles must be rejected as a whole, with the last-known-good policy retained.
- No module may claim to be verified unless a test or live run exercises the real dependency.

## 4. Event Model

### 4.1 Common Requirements

All Shield event records must include enough information to support policy decisions, local audit, and Integrity-backed evidence without capturing raw protected content.

Required principles:

- Preserve canonical field names from shield.schemas.events.
- Use class as the event class key.
- Include time, device_id, and enough event-specific context for policy conditions.
- Do not include raw prompt text, file contents, model output contents, secrets, credentials, patient identifiers, or private documents.
- Prefer opaque IDs, hashes, labels, and resource classes over sensitive payloads.

### 4.2 Event Classes

| Class | Purpose | Current implementation |
|---|---|---|
| process_activity | Process launch/exit and lineage. | ProcessActivity, Linux process-exec sensor verified. |
| file_activity | File create/open/write metadata. | FileActivity, Linux write-open sensor verified. |
| network_flow | Host-attributed outbound flow metadata. | Schema exists; TCP sensor blocked by BCC/kernel version skew. |
| agent_event | Semantic agent/LLM boundary activity. | Guardrail hooks emit/evaluate this shape. |
| policy_decision | Every policy evaluation result. | Router/event log/exporter use this as primary decision evidence. |

### 4.3 PolicyDecision Requirements

Every policy evaluation, including allow and log-only outcomes, must produce a decision record with original event reference, rule reference if matched, final action, operator-readable reason, severity, timestamp, and device context.

## 5. Sensor Specification

### 5.1 Sensor Interface

A sensor is any object satisfying the Sensor protocol in shield/sensors/base.py. It produces an iterator of normalized event objects. The Event Router must not depend on concrete sensor internals.

### 5.2 Dev Sensor

The dev sensor generates synthetic events for local testing, demos, and CLI workflow validation. It must always be labeled synthetic and must never be represented as real endpoint telemetry.

### 5.3 Linux eBPF Sensors

| Probe | Target | Required output | Status |
|---|---|---|---|
| Process execution | execve | PID, process name, executable path, UID/GID when available. | Verified. |
| File write-open | openat write mode | PID, process name, path, operation class. | Verified; userspace sensitive-path glob filtering is config-loadable. |
| TCP connect | tcp_v4_connect | PID/process, destination IP/port, protocol, direction. | Code exists; blocked at compile on current BCC/kernel stack. |
| DNS observation | uprobe or packet parsing design TBD | Query name and resolved IPs without payload capture. | Planned. |

Kernel programs must do the least possible work in kernel space and send compact records to userspace. Any field-offset workaround must be verified against the target kernel BTF or an equivalent reliable source before being treated as real telemetry.

### 5.4 Windows And macOS Sensors

Windows/macOS support is post-Linux. Future sensors must normalize into the same event classes so Agent Core, Policy Engine, Exporter, and CLI remain platform-agnostic.

## 6. Agent Core Specification

### 6.1 DeviceContext

Device context identifies the endpoint and policy scope: device_id, tenant_id, device_role, operating system, and optional posture fields as future extensions.

### 6.2 AgentRegistry

The registry tracks observed agents, tools, and model/API workloads. An agent absent from the registry is treated as unregistered for policy purposes. Registry entries should capture agent/workload ID, display name, type, owner, declared purpose, authority level, and registration state.

### 6.3 EventRouter

The router receives events, attaches context, evaluates policy, invokes applicable guardrail gates, appends local decision logs, submits evidence to the exporter when configured, and returns a decision to the caller. Router behavior must remain deterministic for a given event, registry state, and rule list.

### 6.4 EventLog

The local event log is append-only JSONL used by shield status and shield events. It records policy version/hash when a policy bundle is loaded. It is useful operational evidence but is not tamper-evident until exported and anchored through Integrity Protocol.

## 7. Policy Engine Specification

### 7.1 Rule Model

Rules are JSON records parsed into PolicyRule: rule_id, name, version, scope, conditions, actions, and optional ais_impact hint. The policy engine evaluates rules in list order. First match wins.

### 7.2 Condition Groups

| Group | Matches |
|---|---|
| process | process name/path/PID/user metadata |
| agent | agent registration, authority, owner, workload metadata |
| file | file path/name/extension/type |
| flow | destination/source network tuple and direction |
| context | model endpoint, data sources, tools called |
| activity | activity type, risk level, outcome, policy violation flag |

Unknown fields must not silently match. Path-like values may use glob matching where implemented.

### 7.3 Actions

| Action | Meaning |
|---|---|
| allow | Permit and record. |
| deny | Block the action where pre-action enforcement exists. |
| contain | Contain/terminate process or workload where supported. |
| log_only | Record without enforcement. |
| escalate | Surface to operator or future control plane. |

### 7.4 AIS Impact

ais_impact is a future scoring hint only. Shield must not compute AIS, persist AIS deltas as authoritative, or call private scoring internals. Integrity Oracle remains the only scoring authority.

## 8. Guardrail Hook Specification

Guardrail hooks wrap semantic AI/agent boundaries that OS sensors cannot understand.

| Hook | Timing | Purpose |
|---|---|---|
| Ingress | pre-action | Gate prompt/request source and requesting identity without storing prompt text. |
| Retrieval/context | pre-action | Gate which data sources are added to context. |
| Model routing | pre-action | Gate model/provider/endpoint selection. |
| Output | pre-release | Gate caller-supplied classification labels and risk categories; does not classify content itself. |
| Tool execution | pre-action | Gate concrete tool call/action intent. |
| Post-action verification | post-action | Compare expected vs actual state hash; detect semantic-physical gap. |

Pre-action hooks may block. Post-action verification cannot undo an action; it can only produce evidence, raise, and trigger follow-on containment/escalation.

## 9. Integrity Export Specification

### 9.1 Exporter Responsibilities

The exporter must load or create DID/key identity through integrity-sdk, convert PolicyDecision records into BCC commitments, use integrity_sdk.bcc.build_bcc_commitment for commitment shape/signing, submit telemetry through the public Integrity client, and treat export as best-effort evidence propagation rather than local enforcement authority.

### 9.2 Security Intent Namespace

| Intent type | Meaning |
|---|---|
| shadow_agent_detected | Unregistered agent/tool discovered. |
| agent_contained | Agent process/workload contained or terminated. |
| connection_blocked | Outbound connection denied. |
| guardrail_denied | Agent/LLM boundary action denied. |
| phi_access_attempt | PHI-bearing resource access attempted. |
| device_posture_change | Device risk posture crossed a policy threshold. |

### 9.3 Export Failure Semantics

Export failures must be logged. Local enforcement must not roll back. Retries must be bounded by queue/backpressure controls and must not consume unbounded memory. A local JSONL record without Integrity export is not cryptographic evidence.

## 10. Configuration And Update Specification

Current v1 implementation supports local JSON files for policy rules and device config. It must parse the whole file before replacing live policy, reject malformed bundles as a whole, keep last-known-good policy on reload failure, surface failures through logs/CLI, and attach operator-visible policy version/hash to decisions when rules come from a bundle.

Policy hot reload is mtime-polled and intentionally simple. Future file watchers may replace polling only if they preserve last-known-good semantics.

Tenant cloud policy distribution and safe code auto-update are planned. Code auto-update requires verified downloads, signature checking, staged rollout, rollback, and explicit operator recovery design before implementation.

## 11. CLI And Operator Surface

| Command | Purpose |
|---|---|
| shield status | Summarize local decision log and agent state. |
| shield events --recent N | Show recent local policy decisions. |
| shield validate | Validate policy and device config files. |
| shield run | Run sensor -> router -> policy -> log/exporter loop. |

The CLI must fail with clean errors and no Python traceback for expected operational failures such as non-root eBPF startup.

## 12. Privacy, Data Minimization, And Regulated Environments

Shield follows behavioral telemetry only.

Allowed telemetry includes process metadata, file path/classification metadata, network tuple metadata, agent/workload metadata, model endpoint labels, data-source class labels, risk category labels, and hashes of expected/actual state where needed.

Forbidden telemetry unless a later spec explicitly changes the boundary: raw prompt text, raw model output, file contents, credentials, secrets, patient identifiers, payment credentials, and private documents.

In regulated environments, Shield must tag PHI-bearing resources by class and access event, not inspect records. Any deployment involving ePHI requires separate contractual and operational controls; this repository does not itself create HIPAA compliance.

## 13. Security Model

### 13.1 Trust Assumptions

- Endpoint administrator/root can disable or tamper with local Shield state.
- Integrity-exported evidence becomes tamper-evident only after accepted by Integrity services and anchored according to protocol rules.
- Local JSONL logs are operational records, not cryptographic proof.
- Policy files are trusted local configuration once loaded; future cloud policy requires signed bundles.

### 13.2 Threats Addressed

- Shadow AI process or tool discovery.
- Unauthorized model/tool execution.
- Risky data-source attachment to agent context.
- Policy-relevant outbound network attempts where sensor support exists.
- Evidence gaps where an agent acts but produces no durable audit record.

### 13.3 Threats Not Fully Addressed In v1

- Root-level attacker on the same endpoint.
- Kernel tampering or BPF subsystem compromise.
- Full packet inspection and DNS attribution.
- Content exfiltration detection by payload inspection.
- Windows/macOS endpoint parity.
- Automatic remediation beyond implemented deny/contain hooks.

## 14. Compliance Reporting

Shield does not own a separate compliance export path. Compliance reporting must compose through Integrity Protocol evidence exports so the customer sees one evidence chain instead of parallel logs.

Minimum future report dimensions: device ID and tenant, agent/workload identity, policy version/hash, event class, action/decision, reason and severity, BCC commitment ID/token, anchor/receipt link when available, and export status/gaps.

## 15. Testing And Verification

A Shield capability is real only when pure logic is covered by deterministic unit tests, CLI behavior is covered by subprocess/argparse-level tests, integration behavior reaches a real service or self-skips honestly when unavailable, eBPF behavior is verified under root against real kernel probes, or documentation states the blocker and does not imply capability.

Current test families are listed in [README.md](README.md). New modules must add tests scaled to risk and update both README status and this specification when behavior changes.

## 16. Roadmap

### Phase 1: Linux Enforcement Baseline

- Complete process execution sensor.
- Complete file write sensor.
- Unblock TCP-connect sensor through BCC/kernel compatibility or verified BTF-based struct handling.
- Design DNS observation separately.
- Keep sensitive-path file-event filtering config-loadable and covered by root-free tests.

### Phase 2: Integrity Registration And Evidence Closure

- Register Shield exporter DID with Oracle.
- Verify agent lookup/audit-log query for exported Shield events.
- Re-run resource budget with registered DID and clean exporter queue.
- Add evidence-export examples once INTEGRITY-LATEST reporting surface is ready.

### Phase 3: Policy Distribution And Update Safety

- Design signed policy bundle format.
- Add tenant policy distribution client when a real server exists.
- Specify safe code update mechanism with signature verification and rollback.

### Phase 4: Pilot Readiness

- Package install flow.
- Default policy packs for SMB/professional-services/regulated environments.
- Operator runbook.
- Incident-response workflow.
- Resource and stability burn-in.

### Phase 5: Platform Expansion

- Windows ETW sensor.
- macOS endpoint sensor.
- Optional network appliance/container sensor.
- SIEM/SOAR integrations.

## 17. Acceptance Criteria For v1 Pilot

A Shield v1 pilot is ready when Linux process and file sensors are verified on target pilot kernels; TCP-connect is either verified or explicitly removed from pilot claims; shield run works as a managed service or supervised process; policy rules can be validated and hot-reloaded; local decision logs are inspectable by CLI; exporter reaches live BCC middleware with a registered DID; README status, SECURITY posture, and this specification agree; and a rollback/uninstall procedure exists.

## 18. Revision Policy

Additive clarification may remain v1.0. Any breaking event schema change, policy rule shape change, exporter commitment semantic change, or source-of-truth transfer requires v2 or an explicit migration note. Implementation gaps must be marked as planned, partial, blocked, or verified; silent aspirational claims are not allowed.

*End of specification.*
