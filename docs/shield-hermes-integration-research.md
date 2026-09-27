# Shield ↔ Hermes Integration Research Report

Evidence cutoff: 2026-09-19. This report records the current checkout and live host state
before adding a Shield-to-Hermes integration. Existing dirty worktree changes are preserved.

## 1. Current flow

The verified local enforcement path is:

```text
Linux eBPF process-exec sensor
  -> ProcessActivity normalization
  -> PolicyEngine HTTP request to local OPA
  -> EventRouter
  -> ActionBroker containment (before remote export)
  -> local EventLog JSONL
  -> optional Integrity exporter and asynchronous backend publisher
  -> bounded Cortex SQLite outbox
  -> Cortex HTTP memory API when the outbox worker is active
```

The process-exec sensor is a BCC kprobe/tracepoint path for `execve`. It emits one normalized
event for each observed host execution. `EventRouter.handle()` evaluates every event through
OPA, emits an OpenTelemetry span, optionally exports a signed Integrity decision, and appends
the local decision log. This explains the measured high CPU and JSONL growth: host process
churn is multiplied by synchronous policy evaluation, telemetry serialization, and logging.

The checkout now contains a verified direct Shield-event-to-Hermes local spool producer and
analysis-only consumer path. The UI profile is tenant-scoped and is consumed at agent startup
when the device has an authenticated backend configuration; host spool/key paths remain
operator-managed.
The Hermes `xibalba-shield` profile has an `xibalba_cortex` MCP server pointed at the isolated
`/home/xibalba/.hermes/xibalba-cortex-shield` home and exposes Cortex memory tools, but that is
not an authenticated Shield event transport or acknowledgment path.

## 2. Authority boundaries

- Local Shield sensor observations are facts with bounded, potentially lossy delivery.
- Local deterministic OPA/Rego policy is authoritative for Shield decisions.
- `ActionBroker` is the local enforcement authority for supported containment actions.
- Hermes/cloud reasoning is downstream advisory analysis and cannot override local policy.
- Cortex memory is downstream storage/retrieval and must be treated as untrusted data, never as
  executable instructions or policy authority.
- A requested, authorized, or recommended action is not a completed enforcement outcome.
- Integrity/BCC export and backend/UI publication are downstream of local enforcement and must
  not delay or reverse containment.

## 3. Capability classification

| Capability | Current evidence | Classification |
|---|---|---|
| Linux process-exec sensor | Live `xibalba-shield.service`; process-exec command; historical root-gated tests | Deployment-dependent live, code/test verified |
| OPA/Rego Tier 1 | Live OPA at `127.0.0.1:8181`; `PolicyEngine` calls `/v1/data/shield/policy` | Verified locally; profile identity must be probed per deployment |
| Immediate containment | `ActionBroker` uses SIGSTOP/cgroup freeze before export | Code/test verified; disposable live proof required |
| Local decision log | `/var/log/xibalba-shield/decisions.jsonl` | Verified |
| Integrity export | `integrity_exporter` and BCC SDK path exist | Partial/deployment-dependent |
| Backend evidence publisher | Bounded asynchronous queue with drop/failure counters | Code verified; live endpoint delivery separate |
| Cortex outbox | 16 MiB cap, 64 KiB payload cap, 10-row flush, one worker, retries/dead letters | Code verified; live worker currently inactive |
| Hermes Cortex MCP | Active profile configuration and isolated Cortex home | Configured; Shield event consumer not verified |
| Shield-to-Hermes transport | HMAC-authenticated bounded local spool; startup settings sync; read-only status endpoint | Code/test verified; host deployment-dependent |
| Narrow privileged responder | ActionBroker contains freeze/resume; kill capability disabled by default | Partial; quarantine/block-flow integration not complete |
| UI integration settings | Typed Hermes profile with bounded batch/capacity, strict redaction, analysis-only invariant, and save validation | Code/test verified; rendered browser proof intentionally deferred |

## 4. OPA and policy identity

`shield/policy_engine/engine.py` defaults to `http://localhost:8181` and evaluates the
`/v1/data/shield/policy` package. The live service command uses
`http://127.0.0.1:8181` and the current device policy bundle. The local OPA process observed on
the host was started with the Shield Rego directory and `smb.rego`; the exact package response,
policy version, and hash must be captured by the integration preflight rather than inferred from
the unit command.

Shield policy references carry policy version and hash when a bundle is loaded. The integration
must preserve those fields and reject an event that lacks a valid local policy identity.

## 5. Exporter, outbox, and loss behavior

`CortexMemoryProvider` redacts through `shield.codex_agent.redact_event` before enqueueing. The
SQLite outbox uses WAL and full synchronous mode. Payloads over 64 KiB are dropped and counted;
the total database/WAL footprint is capped at 16 MiB; enqueueing beyond capacity increments a
durable capacity-drop metric. Delivery retries with bounded exponential backoff, transitions to
dead-letter after the configured maximum attempts, and marks acknowledged rows `sent`. Sent rows
are pruned only after one day. The worker flushes at most ten rows per cycle and is configured for
one worker.

The current installed Cortex outbox unit is present but inactive/dead. Therefore configured
durability is not equivalent to live acknowledgment. A future Hermes transport must expose
pending, delivered, dead-letter, dropped, and malformed counters and must not report delivery
success merely because a row was queued.

## 6. Runtime users, capabilities, sockets, and hardening

Live evidence after resource-control activation:

- `xibalba-shield.service`: user/group `xibalba-shield`; `CAP_KILL`; `NoNewPrivileges`;
  `ProtectSystem=strict`; `ProtectHome=read-only`; writable paths limited to Shield config,
  state, and logs; `MemoryMax=128 MiB`; `CPUQuota=25%`; `TasksMax=64`; `LimitNOFILE=2048`.
- `xibalba-shield-ebpf-helper.service`: root with `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`,
  and `CAP_SYS_RESOURCE`; `ProtectSystem=strict`; `ProtectHome=read-only`;
  `MemoryMax=256 MiB`; `CPUQuota=50%`; `TasksMax=64`; `LimitNOFILE=1024`.
- The helper owns `/run/xibalba-shield/ebpf.sock`; the unprivileged agent consumes it.
- The decision log rotates at 100 MiB with seven compressed rotations.
- The Hermes profile is separate from the default Hermes profile and has a distinct Integrity
  identity configured in `config.yaml`; no modification of another profile is authorized.

## 7. Existing Hermes profile and telemetry wiring

`/home/xibalba/.hermes/profiles/xibalba-shield/config.yaml` enables the `xibalba_cortex`
plugin/MCP server with the isolated Cortex home and exposes memory session, remember, end,
recall, and hybrid-retrieve tools. It does not define a Shield Unix socket, spool directory,
event schema consumer, acknowledgment handler, or response-action API. The profile `SOUL.md`
states the intended bounded advisory relationship, but prose is not runtime wiring.

The canonical `/home/xibalba/xibalba-agent/soul.md` is a general Xibalba identity document and
does not authorize Hermes to override Shield policy or operate as a privileged responder.

## 8. Threat model

The integration must defend against:

- PII/secrets in command lines, paths, environment, prompts, model output, tokens, or payloads;
- telemetry injection or schema smuggling through unknown control fields;
- replay and duplicate delivery across restarts;
- unbounded event floods, queue growth, log growth, or Hermes prompt growth;
- policy confusion between local decisions, model classifications, recommendations, and completed
  actions;
- UI/API compromise causing unauthorized settings or action requests;
- privilege escalation through Hermes, arbitrary shell/path/URL fields, or responder misuse;
- stale OPA, stale readiness proofs, dead-letter backlog, dropped events, or missing acks being
  represented as healthy;
- protected-target actions against PID 1, Shield, Hermes, Cortex, backend, or responder itself.

## 9. Required verification and current gaps

Existing focused Shield validation passed 64 tests after the resource-control changes. Systemd
unit verification passed, and the live resource verifier passed after root activation. Root/BPF
sensor proof, live OPA package identity, Cortex worker acknowledgment, Hermes consumer wiring,
UI settings, and disposable responder tests remain separate gates.

The next implementation slice is the versioned JSON contract plus centralized device-side
redaction and preflight assertion. It must be added without changing the local enforcement
authority or treating Hermes/Cortex availability as a prerequisite for containment.
