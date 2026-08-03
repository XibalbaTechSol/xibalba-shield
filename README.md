# Xibalba Shield

Endpoint agent for AI-agent discovery, constraint, and Integrity-backed evidence — device and
network security, **separate from** the HIPAA/healthcare vertical that lives in
[`integrity-latest`](https://github.com/XibalbaTechSol/integrity-latest) (which is also,
confusingly, historically called "Xibalba Shield" — see that repo's
`spec/integrity-protocol-v0.4.md` §14.1 for the split decision).

**Full technical specification (normative):**
[`spec/xibalba-shield-v1.md`](https://github.com/XibalbaTechSol/integrity-latest/blob/main/spec/xibalba-shield-v1.md)
in the parent repo. This README does not duplicate that spec — it tracks *implementation
status against it*. Read the spec first if you're unsure what a module is supposed to do; read
this file to find out whether it actually does it yet.

Xibalba Shield discovers AI agents and tools running on a device, constrains what they can do,
and produces cryptographic evidence of every consequential decision by feeding signed telemetry
into Integrity Protocol. Shield is the sensor and enforcer; Integrity Protocol is the scorer
and archive — neither subsumes the other (spec §1).

**Ground rule, inherited from `integrity-latest` and enforced the same way here: no silent
mocks.** Every row in the table below is either real and tested, or explicitly marked
`[PLANNED]`/`[UNVERIFIED]` with a stated reason. If you add code that isn't fully working, say
so in its own docstring — don't let this README be the only place that admits it.

---

## Status dashboard

Legend: ✅ real & tested · 🟡 real but partially verified (says exactly what's missing) ·
⬜ `[PLANNED]`, no code.

| # | Module | Spec § | Status | Evidence |
|---|---|---|---|---|
| 1 | Event schemas | §5 | ✅ | `shield/schemas/events.py` — exact §5.1–§5.6 shapes, no field renaming. `tests/test_schemas.py` |
| 2 | Policy rule schema | §7 | ✅ | `shield/schemas/policy_rule.py` |
| 3 | Policy Engine | §4.3 | ✅ | `shield/policy_engine/engine.py` — table-driven, first-match, zero network calls. 8 tests in `tests/test_policy_engine.py` |
| 4 | Agent Core — registry, router, event log | §4.2 | ✅ | `shield/agent_core/{registry,router,eventlog}.py`. 7 tests in `tests/test_agent_core.py` |
| 5 | Integrity Exporter | §4.5 | ✅ | `shield/integrity_exporter/exporter.py` — real `integrity-sdk` BCC signing (`bcc.build_bcc_commitment`) + real telemetry (`IntegrityClient.log_telemetry`), no mock. Integration test self-skips if `bcc_middleware` isn't reachable (`tests/test_integrity_exporter.py`) — **not yet run against a live stack in this repo's history; do that before trusting the wire format end-to-end** |
| 6 | Guardrail hook — tool execution (1 of 5) | §4.4 | ✅ | `shield/guardrail_hooks/tool_execution.py` — real pre-execution gate, raises `ToolCallDenied` |
| 7 | Guardrail hooks — ingress, retrieval/context, model routing, output, post-action verification (4 of 5) | §4.4 | ⬜ | Not started. Spec's own build order (§14) puts these after tool execution and after a pilot validates the first one |
| 8 | CLI (`shield status`, `shield events`) | §4.6 | ✅ | `shield/cli.py` |
| 9 | Configuration & update module | §4.6 | ⬜ | Not started — no policy hot-reload, no tenant cloud API, no auto-update |
| 10 | Linux sensor — dev/test generator | §4.1 | ✅ | `shield/sensors/dev_generator.py` — explicitly synthetic, never claims real telemetry |
| 11 | Linux sensor — real eBPF probe | §4.1 | 🟡 **UNVERIFIED** | `shield/sensors/ebpf/{process_exec.bpf.c,loader.py}` — real kprobe-on-`execve` code, written and reviewed. **Nothing about it has been confirmed to actually work.** This machine has `kernel.unprivileged_bpf_disabled=2`, so even checking the C source compiles needs root (BCC's `BPF(text=...)` compiles *and* loads in one call). See "Verifying the eBPF sensor" below — this is the single most important thing to close next |
| 12 | Windows/macOS sensors | §4.1 | ⬜ | `[PLANNED]`, post-Linux per spec §3 |
| 13 | Network sensor (v2+) | §9 | ⬜ | Deferred past v1 per spec §9 — host-centric attribution via the kernel sensor is the v1 design |
| 14 | PHI-tagging / guardrail content classifier | §6 | ⬜ | `[PLANNED]` — behavioral-telemetry-only today; no resource-tagging or content-risk classification exists |
| 15 | AIS contribution mapping | §8 | N/A (design doc only) | Shield does not and must not compute AIS — §8 documents an evidence-shape convention for a future oracle-side change that belongs to `integrity-oracle`, not this repo |
| 16 | Compliance reporting surface | §11 | ⬜ | Depends on `integrity-latest`'s own `docs/design/evidence-export.md` (also `[PLANNED]` there as of this writing) — no separate export path belongs in this repo per spec §11 |
| 17 | Pilot (3–5 SMBs) | §14 step 4 | ⬜ | Blocked on row 11 (Linux sensor verification) |

**One-line summary:** everything that can be built and tested as pure logic (schemas, policy
engine, agent core, one guardrail hook, the exporter's wire format, the CLI) is real. The one
piece needing kernel privileges — the actual Linux eBPF sensor — is written but **not yet
verified to work**, because that verification needs `sudo` on a real machine, not something
achievable from an unprivileged shell alone.

---

## Repository layout

```
shield/
├── agent_core/          # DeviceContext, AgentRegistry, EventRouter, EventLog — §4.2
├── sensors/
│   ├── base.py           # Sensor protocol — real interface
│   ├── dev_generator.py  # DevModeSensor — real, explicitly synthetic
│   └── ebpf/              # process_exec.bpf.c + loader.py — real code, UNVERIFIED (see below)
├── policy_engine/        # Table-driven rule evaluator — §4.3, §7
├── guardrail_hooks/       # tool_execution.py (1 of 5 hook points) — §4.4
├── integrity_exporter/    # Wraps integrity-sdk: BCC signing + telemetry — §4.5
├── schemas/               # Event classes (§5) + policy rule shape (§7)
└── cli.py                 # `shield status` / `shield events --recent` — §4.6
tests/                     # pytest — see "Testing" below for what's real vs. skip-gated
```

**Dependency direction is one-way**, matching spec §2: `xibalba-shield` depends on
`integrity-sdk` (`pyproject.toml`'s git dependency), imported exactly as any third-party agent
runtime would — no privileged API. `integrity-latest` has, and must always have, **zero**
dependency back onto this repo — a kernel-sensor bug here must never be able to affect AIS
computation or Merkle conventions in the parent protocol.

---

## Verifying the eBPF sensor (the one open item that matters most)

This machine has real root access (`sudo`) and real kernel BTF (`/sys/kernel/btf/vmlinux`),
which is exactly what's needed — but `sudo` requires an interactive password this session
could not supply non-interactively. **Run this yourself:**

```bash
cd /home/xibalba/Projects/xibalba-shield
sudo .venv/bin/python -m shield.sensors.ebpf.loader
```

Expected output on success:

```
[self-test] loading LinuxEbpfSensor (requires root)...
[self-test] loaded and attached. Spawning /usr/bin/true as the probe subprocess...
[self-test] observed real exec: pid=NNNNN ppid=NNNNN comm='true' exe='/usr/bin/true'
[self-test] PASS — observed the probe subprocess's own real execve (pid NNNNN).
```

Or run the equivalent as a pytest case (also needs root):

```bash
sudo .venv/bin/python -m pytest tests/test_ebpf_sensor.py -v
```

**Once this passes, update row 11 of the status table above from 🟡 UNVERIFIED to ✅, and
update `shield/sensors/ebpf/loader.py`'s and `process_exec.bpf.c`'s own docstrings** — they
currently say, correctly, that nothing has been confirmed. Don't just flip this README; the
honesty rule means the code's own comments have to agree with it.

If it fails, the most likely causes, in order: (1) the `real_parent->tgid` direct struct
access not matching this kernel's actual layout (unlikely — `linux-headers-7.0.0-28-generic`
is installed and matches `uname -r` exactly, so BCC compiles against the real running kernel's
headers), (2) `get_syscall_fnname("execve")` resolving to a symbol that doesn't exist on this
kernel (check `sudo cat /proc/kallsyms | grep execve`), (3) the perf buffer never receiving
events because the kprobe silently failed to attach (BCC normally raises loudly on this, so a
silent success with zero events is the more suspicious failure mode — check with `sudo bpftool
prog list` that a program is actually loaded).

---

## Quickstart (dev mode — no real sensor required)

```bash
cd /home/xibalba/Projects/xibalba-shield
uv venv --system-site-packages .venv           # --system-site-packages: bcc (python3-bpfcc)
                                                # is a system package, not pip-installable
uv pip install -e ".[dev]" --python .venv/bin/python
.venv/bin/python -m pytest                     # 18 pass, 3 skip (2 need root, 1 needs a live
                                                # bcc_middleware) — see "Testing" below
```

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

Once the eBPF sensor is verified (above), swap `DevModeSensor` for
`shield.sensors.ebpf.loader.LinuxEbpfSensor` — same `events()` interface, same downstream
`ProcessActivity` shape, nothing else changes. That substitutability is the entire reason
`sensors/base.py`'s `Sensor` protocol exists.

---

## Testing

```bash
.venv/bin/python -m pytest                       # everything that's root-free and doesn't need a live stack
sudo .venv/bin/python -m pytest tests/test_ebpf_sensor.py -v   # the two root-gated eBPF tests
```

| Test file | What it actually checks | Needs root? | Needs a live stack? |
|---|---|---|---|
| `test_schemas.py` | Wire-format field names (`class` not `klass`, etc.) | no | no |
| `test_policy_engine.py` | Table-driven rule matching, first-match-wins, scope filtering | no | no |
| `test_agent_core.py` | Registry idempotence, router → policy engine → guardrail → exporter wiring, exception isolation | no | no |
| `test_ebpf_sensor.py` | Non-root construction raises `PermissionError`; (root-gated) BPF source compiles+loads; (root-gated) a real subprocess's real `execve` is observed | 2 of 3 tests, yes | no |
| `test_integrity_exporter.py` | A `PolicyDecision` becomes a real signed BCC commitment and reaches a real `bcc_middleware` | no | yes — self-skips if unreachable |

No test in this repo asserts a fake value against a mock and calls it coverage — every real
test here either exercises pure logic with no external dependency, or self-skips honestly when
its real dependency (root, a live `bcc_middleware`) isn't available, per the convention
`test_integrity_exporter.py` established first.

---

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
- [x] Real Linux eBPF sensor written (kprobe on `execve`, perf ring buffer, normalized output)
- [ ] **Real Linux eBPF sensor verified** — needs `sudo` run, see "Verifying the eBPF sensor" above. **This is the one blocking item in Phase 1.**
- [ ] File open/write hooks on sensitive paths (§4.1 — only process-exec is built so far)
- [ ] TCP-connect/DNS hooks (§4.1 — only process-exec is built so far)

### Phase 2 — Integrity Exporter wired to a real `integrity-sdk` instance
- [x] `IntegrityExporter` built: real DID bootstrap (`integrity_sdk.did.load_or_create_did`), real BCC commitment signing (`integrity_sdk.bcc.build_bcc_commitment`), real telemetry (`IntegrityClient.log_telemetry`)
- [x] `PolicyDecision` → §5.6 `intent_type` mapping table
- [ ] **First real end-to-end signed event, visible in an actual `integrity-oracle` deployment** — the integration test exists and self-skips; it has not yet been run against a live stack from within this repo's history. Bring up `bcc_middleware` (`docker compose up -d bcc-middleware` from `integrity-latest`) and confirm `tests/test_integrity_exporter.py` actually submits, not skips
- [ ] Confirm a Shield-originated commitment is queryable from the oracle side (`GET` the agent's telemetry/audit log and see the `shield_event` payload)

### Phase 3 — Guardrail hooks
- [x] Tool execution hook (`guard_tool_call`) — 1 of 5 hook points, per spec's own sequencing
- [ ] Ingress hook (prompt, requesting identity)
- [ ] Retrieval/context hook (data sources touched)
- [ ] Model routing hook (which model/endpoint)
- [ ] Output hook (content classification — PHI, secrets, risk level) — this is also where §6's PHI-tagging mechanism would plug in
- [ ] Post-action verification hook (the "semantic–physical gap" check — did the expected state change actually occur; see `integrity-protocol-v0.4.md` §22.4)

### Phase 4 — Pilot
- [ ] Blocked on Phase 1's eBPF verification and Phase 2's live-stack proof
- [ ] Resource-budget measurement against spec §3 (≤90MB RAM, ≤3–5% CPU sustained) — **not measured at all yet**, even in dev mode
- [ ] 3–5 friendly SMB pilots, per spec §14

### Phase 5 — Broaden platform/scope
- [ ] Windows sensor (ETW-based, normalized to the same §5 event classes)
- [ ] macOS sensor
- [ ] Network sensor (§9, v2+ per spec — explicitly deferred, not started)
- [ ] Compliance reporting polish (§11) — depends on `integrity-latest`'s own evidence-export work landing first
- [ ] Configuration & update module (§4.6) — policy hot-reload, tenant cloud API, safe auto-update

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
  already-made enforcement decision.

## License

MIT — see `pyproject.toml`.
