# Xibalba Shield

Endpoint agent for AI-agent discovery, constraint, and Integrity-backed evidence — device and
network security, **separate from** the HIPAA/healthcare vertical that lives in
[`integrity-latest`](https://github.com/XibalbaTechSol/integrity-latest). That vertical was
also historically called "Xibalba Shield" before being renamed to **Integrity Health**
(2026-08-04) specifically to remove this ambiguity — see that repo's
`spec/integrity-protocol-v0.4.md` §14.1 for the split decision. "Xibalba Shield" now names only
this product.

**Full technical specification (normative for this repo):**
[`SPECIFICATION.md`](SPECIFICATION.md). The INTEGRITY-LATEST document
[`spec/xibalba-shield-v1.md`](https://github.com/XibalbaTechSol/integrity-latest/blob/main/spec/xibalba-shield-v1.md) records the protocol-facing relationship and integration boundary. Read the spec first if you are unsure what a module is supposed to do; read this README to find out whether it actually does it yet.

Xibalba Shield discovers AI agents and tools running on a device, constrains what they can do,
and produces cryptographic evidence of every consequential decision by feeding signed telemetry
into Integrity Protocol. Shield is the sensor and enforcer; Integrity Protocol is the scorer
and archive — neither subsumes the other (spec §1).

In product-stack terms, **Xibalba Shield is built on top of INTEGRITY-LATEST**. Its endpoint
agent is an upstream evidence producer: it uses INTEGRITY-LATEST's `integrity-sdk`, BCC
middleware, Oracle, and on-chain trust primitives instead of implementing a parallel trust
backend. `integrity-mvp` is the web presentation layer that surfaces Shield alongside the
underlying protocol. The complete direction is
`integrity-mvp -> xibalba-shield -> INTEGRITY-LATEST`, with `integrity-mvp` also consuming
INTEGRITY-LATEST APIs directly.

**Ground rule, inherited from `integrity-latest` and enforced the same way here: no silent
mocks.** Every row in the table below is either real and tested, or explicitly marked
`[PLANNED]`/`[UNVERIFIED]` with a stated reason. If you add code that isn't fully working, say
so in its own docstring — don't let this README be the only place that admits it.

---

## Source-of-truth contract

This README is the repo-level source of truth for Shield implementation status, evidence, testing, and plan. [`SPECIFICATION.md`](SPECIFICATION.md) is the repo-level normative product and implementation specification. INTEGRITY-LATEST owns the protocol primitives Shield consumes; this repository owns Shield endpoint behavior, status, tests, and implementation plan.

## 2026-08-06 audit status

The current audit ledger is [`docs/audits/2026-08-06-status.md`](docs/audits/2026-08-06-status.md). The current root-free suite verifies 66 tests with 7 skips; the README's 2-of-3 verified Linux eBPF status remains current, with TCP-connect blocked by the documented BCC/kernel incompatibility. Shield is a real Linux-first prototype, not production-ready.

If code, tests, comments, and this README disagree, update them in the same change. Shield must never claim to compute AIS, anchor Merkle roots independently, or bypass the public INTEGRITY-LATEST SDK/BCC/Oracle interfaces.

## Status dashboard

Legend: ✅ real & tested · 🟡 real but partially verified (says exactly what's missing) ·
⬜ `[PLANNED]`, no code.

| # | Module | Spec § | Status | Evidence |
|---|---|---|---|---|
| 1 | Event schemas | §5 | ✅ | `shield/schemas/events.py` — exact §5.1–§5.6 shapes, no field renaming. `tests/test_schemas.py` |
| 2 | Policy rule schema | §7 | ✅ | `shield/schemas/policy_rule.py` |
| 3 | Policy Engine | §4.3 | ✅ | `shield/policy_engine/engine.py` — table-driven, first-match, zero network calls. Condition groups: `process`, `agent`, `file`, `flow`, `context`, `activity` (last two added alongside the guardrail hooks below — without them a rule could never match `context.model_endpoint`/`.data_sources` or `activity.risk_level`). Policy decisions include operator-visible policy version/hash when rules are loaded from a bundle. 12 tests in `tests/test_policy_engine.py` |
| 4 | Agent Core — registry, router, event log | §4.2 | ✅ | `shield/agent_core/{registry,router,eventlog}.py`. Router records export success/failure status in local decisions after export attempts. 10 tests in `tests/test_agent_core.py` |
| 5 | Integrity Exporter | §4.5 | ✅ | `shield/integrity_exporter/exporter.py` — real `integrity-sdk` BCC signing (`bcc.build_bcc_commitment`) + real telemetry (`IntegrityClient.log_telemetry`), no mock. **Verified against a live stack**: `tests/test_integrity_exporter.py` submitted for real and got `authorized: true` + a real `verification_token`/`batch_index` back from `bcc_middleware`. The bootstrapped DID isn't registered with the oracle, so `GET /v1/agent/{did}` 404s — a separate, heavier follow-on step (see Phase 2 below) |
| 6 | Guardrail hooks — all 6 hook points | §4.4 | ✅ | `shield/guardrail_hooks/{ingress,retrieval_context,model_routing,output,tool_execution,post_action_verification}.py` — each a real pre- (or, for post-action, post-) decision gate with its own deny exception. 15 tests in `tests/test_guardrail_hooks.py`. Repo-local `SPECIFICATION.md` resolves the prior wording drift by treating §4.4's enumerated six hooks as authoritative. |
| 7 | CLI (`shield status`, `shield events`, `shield validate`, `shield run`) | §4.6 | ✅ | `shield/cli.py`. `shield run` is the real entry point — wires a real `Sensor` (`process-exec`/`file-write`/`dev`) into a real `EventRouter`/`PolicyEngine`/`EventLog`, with hot-reload if `--rules` is given and a real `IntegrityExporter` unless `--no-exporter`. `shield events` prints export status. Verified end-to-end live: `dev` sensor with a real deny rule correctly denied every `network_flow` event and nothing else; `process-exec`/`file-write` correctly raise a clean `PermissionError` (exit 1, no traceback) when not run as root. |
| 8 | Configuration & update module | §4.6 | 🟡 | `shield/config/{loader,hot_reload}.py` — **real**: `load_policy_bundle` computes `policy_version` and `sha256` over the exact bundle bytes; `load_policy_rules`/`load_device_config` parse local JSON files into the real `PolicyRule`/`DeviceConfig` shapes; `DeviceConfig.sensitive_paths` configures file-write filtering; `trusted_policy_hashes` can pin known-good bundles at startup and hot reload; malformed input refuses the whole bundle loudly. Tenant cloud API and safe code auto-update remain planned. |
| 9 | Linux sensor — dev/test generator | §4.1 | ✅ | `shield/sensors/dev_generator.py` — explicitly synthetic, never claims real telemetry |
| 10 | Linux sensors — real eBPF probes (3) | §4.1 | 🟡 **2 of 3 VERIFIED** | `shield/sensors/ebpf/{process_exec,file_write,tcp_connect}.bpf.c` + `loader.py`. **process-exec ✅ VERIFIED** (kprobe on `execve`, observed a real spawned subprocess's real exec). **file writes ✅ VERIFIED** (kprobe+kretprobe on `openat`, filtered to write-mode in-kernel, observed a real write-open; userspace sensitive-path glob filtering is now wired from `DeviceConfig.sensitive_paths`). **TCP-connect 🔴 BLOCKED**, confirmed a BCC/kernel version-skew problem rather than a bug here. DNS observation is NOT built at all. See "Verifying the eBPF sensors" below and `shield/sensors/ebpf/README.md` for the full record |
| 11 | Windows/macOS sensors | §4.1 | ⬜ | `[PLANNED]`, post-Linux per spec §3 |
| 12 | Network sensor (v2+) | §9 | ⬜ | Deferred past v1 per spec §9 — host-centric attribution via the kernel sensor is the v1 design |
| 13 | PHI-tagging / guardrail content classifier | §6 | ⬜ | `[PLANNED]` — behavioral-telemetry-only today; the output hook (row 6) enforces policy on a classification but does not itself produce one. No resource-tagging or content-risk classification exists |
| 14 | AIS contribution mapping | §8 | N/A (design doc only) | Shield does not and must not compute AIS — §8 documents an evidence-shape convention for a future oracle-side change that belongs to `integrity-oracle`, not this repo |
| 15 | Compliance reporting surface | §11 | ⬜ | Depends on `integrity-latest`'s own `docs/design/evidence-export.md` (also `[PLANNED]` there as of this writing) — no separate export path belongs in this repo per spec §11 |
| 16 | Pilot (3–5 SMBs) | §14 step 4 | ⬜ | Blocked on row 10 (Linux sensor verification) |

**One-line summary:** everything that can be built and tested as pure logic (schemas, policy
engine, agent core, all six guardrail hooks, the exporter's wire format, the CLI) is real, the
exporter's wire path is proven against a live `bcc_middleware`, and 2 of 3 Linux eBPF sensors
(process-exec, file-write) are now live-verified on real kernel probes. The third
(TCP-connect) is confirmed BLOCKED by a BCC/kernel version-skew problem — not a bug in this
repo's code, reproduced with BCC's own shipped `tcpconnect-bpfcc` tool — see "Verifying the
eBPF sensors" below.

---

## Repository layout

```
shield/
├── agent_core/          # DeviceContext, AgentRegistry, EventRouter, EventLog — §4.2
├── sensors/
│   ├── base.py           # Sensor protocol — real interface
│   ├── dev_generator.py  # DevModeSensor — real, explicitly synthetic
│   └── ebpf/              # process_exec.bpf.c + file_write.bpf.c: VERIFIED. tcp_connect.bpf.c:
│                           # BLOCKED (BCC/kernel version-skew, confirmed environment limit)
├── policy_engine/        # Table-driven rule evaluator — §4.3, §7
├── guardrail_hooks/       # all 6 hook points (ingress, retrieval/context, model routing,
│                           # output, tool_execution, post_action_verification) — §4.4
├── integrity_exporter/    # Wraps integrity-sdk: BCC signing + telemetry — §4.5
├── config/                # Local-file policy/device config loader + PolicyHotReloader — §4.6
│                           # (cloud API + code auto-update deliberately not built, row 8)
├── schemas/               # Event classes (§5) + policy rule shape (§7)
└── cli.py                 # `shield status` / `events` / `validate` / `run` — §4.6. `run`
                            # is the real entry point: sensor -> router -> policy -> exporter
packaging/systemd/          # Managed Linux service unit and environment example
policies/defaults/          # SMB, professional-services, and regulated default policy packs
scripts/                   # measure_resource_budget.py — spec §3 budget, real numbers recorded below
tests/                     # pytest — see "Testing" below for what's real vs. skip-gated
```

**Dependency direction is one-way**, matching spec §2: `xibalba-shield` depends on
`integrity-sdk` (`pyproject.toml`'s git dependency), imported exactly as any third-party agent
runtime would — no privileged API. `integrity-latest` has, and must always have, **zero**
dependency back onto this repo — a kernel-sensor bug here must never be able to affect AIS
computation or Merkle conventions in the parent protocol.

---

## Verifying the eBPF sensors — done, 2026-08-04: 2 of 3 pass, 1 confirmed blocked

Reproduce with:

```bash
cd /home/xibalba/Projects/xibalba-shield
sudo .venv/bin/python -m shield.sensors.ebpf.loader
```

Actual output, this machine:

```
[self-test:process_exec] PASS — observed pid 395017's real execve.
[self-test:file_write] PASS — observed this process's real write open of '/tmp/tmpy55g1m83-shield-self-test'.
[self-test:tcp_connect] Exception: Failed to compile BPF module <text>
```

**process-exec and file-write are real, live-verified sensors.** TCP-connect fails to
*compile* (not load/attach) because its `#include <net/sock.h>` pulls in kernel headers
referencing very recent additions (`struct bpf_wq`, `BPF_LOAD_ACQ`, `BPF_F_CPU`, `struct
ns_common.ns_id`) that BCC 0.29.1's bundled compatibility headers don't know about yet. This
was confirmed to be a genuine BCC/kernel version-skew problem, not a bug in
`tcp_connect.bpf.c`: BCC's own shipped, pre-tested `tcpconnect-bpfcc` binary
(`sudo timeout 3 tcpconnect-bpfcc`) hits an equivalent failure on the identical `net/sock.h`
chain, on this same machine. See `tcp_connect.bpf.c`'s own comment for the full record,
including why a hand-rolled `struct sock_common` workaround was deliberately not attempted
blind (risk of silently-wrong IP/port data from an unverifiable field-offset guess).

Or run the equivalent as pytest cases (also needs root):

```bash
sudo .venv/bin/python -m pytest tests/test_ebpf_sensor.py -v
```

Row 10 above, `shield/sensors/ebpf/loader.py`'s module docstring, each of the three `.bpf.c`
files' own comments, and `shield/sensors/ebpf/README.md` are all updated to match this result
— process-exec and file-write marked ✅ VERIFIED with the specific evidence, TCP-connect
marked 🔴 BLOCKED with the specific root cause and the reasoning for not attempting a blind
workaround. **Unblocking TCP-connect needs either a newer BCC release or someone who can
verify `struct sock_common`'s real field layout against this kernel's own BTF** (`bpftool btf
dump file /sys/kernel/btf/vmlinux`) before hand-rolling a minimal mirror struct that avoids
`net/sock.h`'s header chain.

---

## Quickstart (dev mode — no real sensor required)

```bash
cd /home/xibalba/Projects/xibalba-shield
uv venv --system-site-packages .venv           # --system-site-packages: bcc (python3-bpfcc)
                                                # is a system package, not pip-installable
uv pip install -e ".[dev]" --python .venv/bin/python
.venv/bin/python -m pytest                     # 66 passed, 7 skipped in the current
                                                # root-free suite — see "Testing" below
```

`shield run` is the real entry point — it wires a real `Sensor` into a real `EventRouter`,
end to end, with `shield status`/`events` reading back what it produced:

```bash
# Synthetic events, no root, no exporter -- fastest way to see the whole loop work:
.venv/bin/shield run --sensor dev --device-id dev-1 --no-exporter --max-events 10

# The two VERIFIED real eBPF sensors -- need root (see "Verifying the eBPF sensors" above):
sudo .venv/bin/shield run --sensor process-exec --device-id dev-1 --no-exporter
sudo .venv/bin/shield run --sensor file-write --device-id dev-1 --no-exporter

# Real policy enforcement + real exporter (needs bcc_middleware up, see its own repo):
.venv/bin/shield run --sensor dev --device-id dev-1 --rules rules.json \
    --bcc-middleware-url http://localhost:8000 --max-events 20
# --rules is hot-reloaded: edit rules.json while `run` is going and the next check picks
# it up, or falls back to the last-known-good rule set if the edit doesn't parse.

.venv/bin/shield --log-path ~/.xibalba-shield/decisions.jsonl status
.venv/bin/shield --log-path ~/.xibalba-shield/decisions.jsonl events --recent 20
```

`--max-events N` stops after N events (useful for demos/scripts); omit it to run forever
until Ctrl+C. `shield run --help` lists every flag (`--device-config`/`--tenant-id`/
`--device-role`/`--oracle-url`/`--agent-label`/`--dev-interval`, ...).

For programmatic use instead of the CLI, the same pieces compose directly — `EventRouter`
just needs a `Sensor`, a `PolicyEngine`, an exporter, and an `EventLog`:

```python
from shield.agent_core import AgentRegistry, DeviceContext, EventLog, EventRouter
from shield.integrity_exporter import IntegrityExporter
from shield.policy_engine import PolicyEngine
from shield.sensors import DevModeSensor

device = DeviceContext(device_id="dev-1", tenant_id="local-dev", device_role="workstation")
router = EventRouter(
    device=device,
    registry=AgentRegistry(),
    policy_engine=PolicyEngine(rules=[]),  # load real rules per spec §7 for actual policy
    exporter=IntegrityExporter(bcc_middleware_url="http://localhost:8000"),
    event_log=EventLog(path=...),
)
for event in DevModeSensor(device_id="dev-1").events():
    router.handle(event)
```

Swap `DevModeSensor` for `shield.sensors.ebpf.loader.LinuxEbpfSensor`/`LinuxFileWriteSensor`
(both VERIFIED, see above) for the same `events()` interface over real kernel events, nothing
else changes — that substitutability is the entire reason `sensors/base.py`'s `Sensor`
protocol exists, and it's exactly what `shield run --sensor process-exec` does under the hood.

---

## Testing

```bash
.venv/bin/python -m pytest                       # everything that's root-free and doesn't need a live stack
sudo .venv/bin/python -m pytest tests/test_ebpf_sensor.py -v   # the 6 root-gated eBPF tests
```

| Test file | What it actually checks | Needs root? | Needs a live stack? |
|---|---|---|---|
| `test_schemas.py` | Wire-format field names (`class` not `klass`, etc.) | no | no |
| `test_policy_engine.py` | Table-driven rule matching, first-match-wins, scope filtering | no | no |
| `test_agent_core.py` | Registry idempotence, router → policy engine → guardrail → exporter wiring, exception isolation | no | no |
| `test_guardrail_hooks.py` | All 6 hook points: allow-path invokes the wrapped call, deny-path raises the hook's own exception AND never invokes the call | no | no |
| `test_ebpf_sensor.py` | All 3 sensors: non-root construction raises `PermissionError` (root-free); (root-gated) BPF source compiles+loads; (root-gated) a real triggered event (exec/write/connect) is observed | 6 of 9 tests, yes | no |
| `test_integrity_exporter.py` | A `PolicyDecision` becomes a real signed BCC commitment and reaches a real `bcc_middleware` | no | yes — self-skips if unreachable |
| `test_config.py` | Real JSON files loaded through `load_policy_bundle`/`load_policy_rules`/`load_device_config` — file order preserved, policy hash/version computed, malformed input refuses the whole bundle loudly (missing file, bad JSON, wrong shape, unknown field, one bad rule among good ones) | no | no |
| `test_cli.py` | `shield validate` and `shield run` end-to-end through real argparse wiring — `run` exercises the real `EventRouter`/`PolicyEngine`/`EventLog` with the `dev` sensor (real policy decisions logged, hot-reload wired), plus `process-exec`'s `PermissionError` surfacing cleanly when not root | no | no |
| `test_hot_reload.py` | `PolicyHotReloader` against real files with real mtime changes — picks up a real edit, ignores an unchanged file, and (the core safety property) a malformed edit or a missing file keeps the engine on its last-known-good rules rather than zeroing them out | no | no |

No test in this repo asserts a fake value against a mock and calls it coverage — every real
test here either exercises pure logic with no external dependency, or self-skips honestly when
its real dependency (root, a live `bcc_middleware`) isn't available, per the convention
`test_integrity_exporter.py` established first.

---

## Documentation map

| Document | Purpose |
|---|---|
| [README.md](README.md) | Current implementation status, evidence, test commands, and plan |
| [SPECIFICATION.md](SPECIFICATION.md) | Normative Shield product and implementation specification |
| [SECURITY.md](SECURITY.md) | Security handling and disclosure expectations |
| [docs/archive/2026-08-06/HANDOFF.md](docs/archive/2026-08-06/HANDOFF.md) | Historical operational handoff notes |
| [CLAUDE.md](CLAUDE.md) | Local agent instructions for this repository |
| [shield/sensors/ebpf/README.md](shield/sensors/ebpf/README.md) | eBPF sensor verification record and blocked TCP-connect analysis |
| [docs/design/signed-policy-bundles.md](docs/design/signed-policy-bundles.md) | Signed policy bundle format and current trusted-hash enforcement |
| [INTEGRITY-LATEST spec/xibalba-shield-v1.md](https://github.com/XibalbaTechSol/integrity-latest/blob/main/spec/xibalba-shield-v1.md) | Protocol-facing Shield integration boundary |
| [INTEGRITY-LATEST docs/wiki/architecture/ecosystem-dependencies.md](https://github.com/XibalbaTechSol/integrity-latest/blob/main/docs/wiki/architecture/ecosystem-dependencies.md) | Cross-repo dependency boundary |

## Implementation plan (spec §14's build order, expanded)

Checkboxes track *this repo's* state, not the spec's aspirations. Update them as items land —
this section **is** the project's task list; don't let it drift out of sync with the status
table above (if they disagree, the status table is more detailed and wins).

### Phase 1 — Linux agent core + eBPF sensor + local policy engine, zero cloud dependency
- [x] Event schemas (§5) — exact shapes, tested
- [x] Policy rule schema (§7)
- [x] Policy Engine (§4.3) — table-driven, first-match, zero network calls
- [x] Agent Core: `DeviceContext`, `AgentRegistry`, `EventRouter`, `EventLog` (§4.2)
- [x] Dev-mode synthetic sensor, for testing everything above before a real sensor exists
- [x] Real Linux eBPF sensor written AND **VERIFIED** (kprobe on `execve`, perf ring buffer, normalized output) — observed a real spawned subprocess's real exec, 2026-08-04
- [x] File write hooks written AND **VERIFIED** (`file_write.bpf.c` — kprobe+kretprobe on `openat`, filtered to `O_WRONLY`/`O_RDWR` in-kernel) — observed the test process's own real write-open, 2026-08-04. Userspace sensitive-path glob filtering is wired through `DeviceConfig.sensitive_paths`.
- [ ] **TCP-connect hooks written, BLOCKED at verification** (`tcp_connect.bpf.c` — kprobe+kretprobe on `tcp_v4_connect`, IPv4 only). Confirmed a BCC/kernel version-skew problem (BCC's own `tcpconnect-bpfcc` fails identically), not a bug in this file — see "Verifying the eBPF sensors" above. **This is the one remaining blocking item in Phase 1.**
- [ ] DNS hooks — not built at all. Needs a uprobe on libc's `getaddrinfo` or UDP:53 payload parsing, a different mechanism than a syscall kprobe; deferred rather than built un-reviewed alongside the other three this pass

### Phase 2 — Integrity Exporter wired to a real `integrity-sdk` instance
- [x] `IntegrityExporter` built: real DID bootstrap (`integrity_sdk.did.load_or_create_did`), real BCC commitment signing (`integrity_sdk.bcc.build_bcc_commitment`), real telemetry (`IntegrityClient.log_telemetry`)
- [x] `PolicyDecision` → §5.6 `intent_type` mapping table
- [x] Local decisions and exported decision payloads include policy version/hash when rules are loaded from a policy bundle
- [x] Local decisions include export status, and `shield events` prints `export=ok|failed|not_attempted`
- [x] **First real end-to-end signed event, verified against a live `bcc_middleware`** — brought up `postgres`/`redis`/`opa`/`oracle-backend`/`bcc-middleware` from `integrity-latest` and ran `tests/test_integrity_exporter.py`: it submitted for real (not skipped), got back a real structured response with `authorized: true`, a `verification_token`, and `batch_index: 3` — concrete proof of admission into `bcc_middleware`'s real Merkle batch (`app/merkle.py`'s pipeline step 7), not just an echoed `authorized` flag
- [ ] **Not yet done: full oracle registration + audit-log query.** `GET /v1/agent/{did}` 404s for the exporter's bootstrapped DID (`did:integrity:e39591ab…`) — it was never registered with the oracle (`POST /v1/agent/register`, which needs a funded wallet and an on-chain tx). That's a separate, heavier step than proving the wire path works; the commitment reaching a real Merkle batch is the Phase 2 milestone this checklist item originally asked for, registration/audit-log visibility is follow-on work

### Phase 3 — Guardrail hooks
- [x] Tool execution hook (`guard_tool_call`)
- [x] Ingress hook (`guard_ingress`) — prompt, requesting identity. No prompt *content* in the event (§6) — only `agent`/`owner_user_id`
- [x] Retrieval/context hook (`guard_retrieval`) — data sources touched, matched via the new `context` condition group
- [x] Model routing hook (`guard_model_routing`) — which model/endpoint, matched via `context.model_endpoint`
- [x] Output hook (`guard_output`) — gates on a caller-supplied `risk_level`/`categories` classification; **does not itself classify content** — that's §6's still-`[PLANNED]` PHI-tagging/classifier, a separate piece of real work
- [x] Post-action verification hook (`verify_post_action`) — the "semantic–physical gap" check (expected vs. actual state hash equality; see `integrity-protocol-v0.4.md` §22.4). Structurally different from the other five: the action already happened, so this can only detect and flag, never block
- [x] Policy Engine extended with `context` and `activity` condition groups — without them, rules could never actually gate on the fields these five new hooks carry (model_endpoint, data_sources, risk_level), making them decorative rather than enforcing
- [x] 15 new tests (`tests/test_guardrail_hooks.py`) + 3 new policy-engine tests for the two new condition groups — every hook tested both directions: allow invokes the call, deny raises AND never invokes it

### Phase 4 — Pilot
- [x] **Resource-budget measurement against spec §3 (≤90MB RAM, ≤3–5% CPU sustained) — done, 2026-08-04.** `scripts/measure_resource_budget.py`, real numbers (`resource.getrusage`, not estimated):

  | Scenario | Events | CPU (at that rate) | Peak RSS |
  |---|---|---|---|
  | STRESS, no exporter | 702,302 in 15s | 99.72% (saturated by design — see below) | 16.4 MB |
  | IDLE (1/sec), no exporter | 16 in 15s | 0.02% | 16.4 MB |
  | STRESS, real exporter | 38 in 15s | 1.12% (network-bound, not CPU-bound) | 61.0 MB |
  | IDLE (1/sec), real exporter | 13 in 16s | 0.56% | 61.0 MB |

  **Verdict: within budget, but not by a huge margin on the exporter path.** Projected CPU
  at a genuinely busy device (10 events/sec, from measured per-event cost, not the
  meaningless STRESS raw-% number): **4.425%**, against a 5% ceiling. Peak RSS **61.0 MB**,
  against a 90 MB ceiling (~68% consumed). The no-exporter numbers (16.4 MB, negligible CPU)
  show the agent-core/policy-engine loop itself is cheap — essentially all of the budget
  consumption comes from the real exporter's DID/keypair/HTTP-client footprint and
  BCC-signing cost, which is the same for one event or ten thousand.

  **Caveat, stated plainly:** the exporter scenarios hit the same oracle-registration gap
  Phase 2 already found — the benchmark's ad-hoc DID isn't registered, so telemetry flush
  fails with 404 and retries/re-queues, which likely inflates RSS above a clean steady-state
  number. Re-run against a registered DID for a tighter figure before treating 61.0 MB as
  final. **Does NOT include real eBPF kernel-sensor overhead** — that runs in kernel space
  with a cheap perf-buffer handoff, a different (and expected to be much smaller) cost than
  this script measures; a separate root-run measurement would be needed for the full
  picture including the two verified sensors.
- [x] Managed Linux service packaging exists: `packaging/systemd/xibalba-shield.service`, `packaging/systemd/shield.env.example`, and `docs/runbooks/linux-agent.md`
- [x] Default policy packs exist for SMB, professional services, and regulated environments under `policies/defaults/`
- [ ] Blocked on TCP-connect eBPF verification (environment-limited, see Phase 1) and registered exporter DID verification for the full pilot picture
- [ ] 3–5 friendly SMB pilots, per spec §14

### Phase 5 — Broaden platform/scope

Three items below are **blocked, not just unstarted** — stated explicitly so "not done" doesn't
read as "next up": Windows/macOS sensors need a Windows/macOS machine to write AND verify
against (this has only ever been a Linux box); the network sensor is deferred past v1 by the
spec's own text (§9), not an oversight; compliance reporting polish depends on
`integrity-latest`'s own evidence-export work, whose Phase B/C (control mapping, the actual
export endpoint) are confirmed still `🔨 not built` there as of this check.

- [ ] Windows sensor (ETW-based, normalized to the same §5 event classes) — **blocked**, no Windows machine available to write and verify against
- [ ] macOS sensor — **blocked**, same reason
- [ ] Network sensor (§9, v2+ per spec — explicitly deferred, not started) — **not a gap**, the spec itself says defer this
- [ ] Compliance reporting polish (§11) — **blocked upstream**, `integrity-latest/docs/design/evidence-export.md` Phase B/C not built there yet
- [x] Configuration & update module (§4.6), **local-file half + hot-reload**: `shield/config/loader.py` — real `load_policy_rules`/`load_device_config`, wired into `shield validate`. `shield/config/hot_reload.py::PolicyHotReloader` — mtime-polled, reloads a changed rules file into a live `PolicyEngine` without restarting; a malformed edit keeps the engine on its last-known-good rules rather than zeroing them out or crashing. 22 new tests total (11 loader + 5 CLI + 6 hot-reload)
- [ ] Tenant cloud API for policy distribution — deliberately not built; no real server exists anywhere in this monorepo or `integrity-latest` to verify a client against
- [ ] Safe auto-update for agent *code* (not policy bundles, which hot-reload now covers) — deliberately not built; a materially harder problem (verified downloads, rollback, update-payload signature checking) than a config loader, deserves its own design pass

### Not in any phase — explicitly out of scope per spec §13
- Not a payment rail, custodial key service, or trust-scoring engine (that's Integrity Protocol's job)
- Not a full EDR/XDR replacement in v1
- Not a second place AIS is computed, not a second evidence-anchoring mechanism
- Not multi-OS at v1 (Linux-first is a scope decision, not a limitation)
- Not a content-inspection/DLP product (behavioral telemetry only, §6)

---

## Cross-repo conventions inherited from `integrity-latest`

- **BCC commitment shape is frozen** (`docs/INTERFACE_CONTRACT.md` in the parent repo) — this
  repo's `integrity_exporter` must never invent its own commitment fields; it calls
  `integrity_sdk.bcc.build_bcc_commitment` and nothing else builds one.
- **AIS is computed in exactly one place**, `integrity-oracle/scoring-core` in the parent repo.
  Nothing in this repo may compute or approximate an AIS delta itself — `schemas/policy_rule.py`'s
  `ais_impact` field is a *hint* for a future oracle-side mapping layer, never a direct score
  write from here.
- **Fail-open/fail-closed postures are stated explicitly per module** — see `router.py`'s own
  docstring on why a guardrail-hook exception or an export failure never rolls back an
  already-made enforcement decision, and [`SECURITY.md`](SECURITY.md) for the consolidated,
  code-grounded threat model this all adds up to.

## Security posture

[`SECURITY.md`](SECURITY.md) states plainly what this repo's code actually enforces today
versus what `spec/xibalba-shield-v1.md` §6/§13 describe as design intent — default-allow
posture, what a co-located root attacker can defeat, what's evidenced vs. merely logged
locally, and what's real vs. still `[PLANNED]`. Read it before representing any capability to
a customer, auditor, or pilot.

## License

MIT — see `pyproject.toml`.
