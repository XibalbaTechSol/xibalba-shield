# Handoff — 2026-08-04

> **Current audit pointer — 2026-08-06:** Use [`docs/audits/2026-08-06-status.md`](docs/audits/2026-08-06-status.md) for current repository status. This handoff remains a historical execution record.

Read this first if picking up `xibalba-shield`. `README.md` is the living, per-module status
dashboard and phase checklist — this file is the narrative: what happened this session, what's
actually verified vs. blocked, and what to do next, in order. Nothing below is inferred; every
claim was executed and its output is quoted or referenced.

## 0. Where this repo started

Not built from scratch. A prior session had already scaffolded a real, tested Python core
(schemas, Policy Engine, Agent Core, one guardrail hook, the Integrity Exporter, the CLI) with
the eBPF sensor honestly marked `[PLANNED]`. This session built on that rather than discarding
it — see the repo's own git history (`1196076` is the original scaffold commit) for the exact
starting line.

## 1. What this session actually did, phase by phase

**Phase 1 (Linux sensors).** Wrote three real eBPF programs (`process_exec.bpf.c`,
`file_write.bpf.c`, `tcp_connect.bpf.c`) and their userspace loaders. Verified live, with
`sudo`, on the real target machine:
- `process_exec`: **PASS** — observed a real spawned subprocess's real `execve`.
- `file_write`: **PASS** — observed the test process's own real write-mode `openat`.
- `tcp_connect`: **BLOCKED**, confirmed environmental, not a code bug — `#include
  <net/sock.h>` hits kernel headers this machine's BCC 0.29.1 can't parse. Proved this isn't
  our code's fault by running BCC's own shipped `tcpconnect-bpfcc` binary and watching it fail
  the identical way. Didn't attempt a blind `struct sock_common` workaround — a wrong
  hand-guessed field offset would silently produce plausible-looking but wrong IP/port data,
  worse than the current honest compile failure.

**Phase 2 (Integrity Exporter live-stack proof).** Brought up `postgres`/`redis`/`opa`/
`oracle-backend`/`bcc-middleware` from `integrity-latest` and ran the exporter for real:
`authorized: true`, a real `verification_token`, `batch_index: 3` — genuine Merkle-batch
admission, not an echoed flag. Open: the exporter's bootstrapped DID isn't registered with the
oracle, so `GET /v1/agent/{did}` 404s (needs a funded wallet + on-chain tx, separate work).

**Phase 3 (guardrail hooks).** Built the 5 remaining hook points beyond `tool_execution`:
`guard_ingress`, `guard_retrieval`, `guard_model_routing`, `guard_output`,
`verify_post_action`. Had to extend the Policy Engine with `context` and `activity` condition
groups first — without them, 3 of the 5 new hooks would have been decorative (no rule could
ever match `model_endpoint`, `data_sources`, or `risk_level`).

**Phase 4 (resource budget).** Real measurement (`scripts/measure_resource_budget.py`,
`resource.getrusage`, no new dependency). Agent-core + policy engine alone: negligible (~21
µs/event, 16.4 MB RSS). The real exporter is where the budget goes: **61.0 MB peak RSS**,
**4.425% projected CPU** at a busy device's rate (10 events/sec) — both within spec §3's
90 MB / 5% ceiling, but not by a large margin. Caveat on record: the benchmark DID's telemetry
kept 404ing (same registration gap as Phase 2) and re-queuing, which likely inflates that RSS
number above a clean steady-state figure — re-run against a registered DID for a tighter one.

**Phase 5 (config module).** Built the two pieces that don't need a server to test against:
`shield/config/loader.py` (real local-file JSON loading for policy rules + device config,
refuses the whole bundle loudly on any malformed entry) and `shield/config/hot_reload.py`
(`PolicyHotReloader` — reloads a changed rules file into a live engine without a restart; a
bad edit keeps the engine on its last-known-good rules instead of zeroing them out). Both
wired into a new `shield validate` CLI command. Explicitly did NOT build: Windows/macOS
sensors (no such machine to verify against), the network sensor (spec §9 defers it past v1,
not a gap), compliance reporting (checked `integrity-latest`'s `docs/design/evidence-export.md`
directly — Phase B/C confirmed still not built there), tenant cloud API, or code auto-update
(both need infrastructure/design work this session couldn't responsibly fake).

## 2. A mid-session detour worth knowing about

Bringing `bcc-middleware` live (for Phase 2's proof) tripped a real policy check in the
*separate* `integrity-latest` session harness (`~/.claude/xibalba/`): `bcc.rego`'s AOS
observability rule requires a real OpenTelemetry trace/span in every gated commitment, and
nothing had ever wired one across the per-tool-call subprocess boundary. That's unrelated to
this repo's code but blocked all further work until fixed — see that repo's own session log /
`~/.claude/xibalba/_common.py`'s `persist_session_traceparent`/`load_session_traceparent` for
the permanent fix, if it's ever relevant here again (e.g. if `xibalba-shield`'s own future
Claude Code sessions hit the same wall).

## 3. State of the tree

| Check | Result |
|---|---|
| `pytest` (no root, no live stack needed) | Historical value: **58 passed**, 6 honest skips. Current 2026-08-06 root-free suite after follow-up implementation: **66 passed**, 7 skipped |
| `pytest` with `bcc-middleware` up | same 58, minus the exporter test's skip — it passes for real |
| `sudo python3 -m shield.sensors.ebpf.loader` | 2/3 sensors PASS, 1 BLOCKED (see Phase 1 above) |
| `scripts/measure_resource_budget.py` | within spec §3 budget, real numbers recorded in README |
| Every module's own docstring vs. README's status table | **checked to agree** — this was re-verified explicitly after each change, not assumed |

## 4. Next, in priority order

1. **Unblock `tcp_connect.bpf.c`.** Needs either a newer BCC release, or someone who can
   verify `struct sock_common`'s real field layout against this kernel's own BTF
   (`bpftool btf dump file /sys/kernel/btf/vmlinux`) before hand-rolling a minimal mirror
   struct that avoids `net/sock.h`'s header chain. Don't guess the offsets blind.
2. **Register the exporter's DID with the oracle** (`POST /v1/agent/register`, needs a funded
   wallet) so Phase 2's `GET /v1/agent/{did}` 404 closes, and re-run the resource-budget
   exporter scenarios against a registered DID for a cleaner RSS figure (see the caveat in
   §1's Phase 4 paragraph).
3. ~~**Wire a real sensor into `agent_core.router`.**~~ **DONE (2026-08-04).** `shield run
   --sensor {process-exec,file-write,dev}` is the real entry point now (`shield/cli.py`) —
   wires a real `Sensor` into a real `EventRouter`/`PolicyEngine`/`EventLog`, with hot-reload
   if `--rules` is given and a real `IntegrityExporter` unless `--no-exporter`. Verified live:
   the `dev` sensor with a real deny rule correctly denied every `network_flow` event and
   nothing else; `process-exec`/`file-write` raise a clean `PermissionError` (exit 1, no
   traceback) when not root. 5 new tests. "The sensor works" and "the sensor is actually
   running" are no longer different claims for `process-exec`/`file-write`.
4. **Pilot (Phase 4's other half).** Genuinely blocked until #1 closes — 3–5 SMB pilots need
   the full sensor picture, not 2 of 3.
5. Everything in Phase 5's blocked list (§1 above) once its respective blocker clears.

## 5. Running the stack

```bash
cd /home/xibalba/Projects/xibalba-shield
uv venv --system-site-packages .venv && uv pip install -e ".[dev]" --python .venv/bin/python
.venv/bin/python -m pytest                                          # 58 pass, 6 skip
sudo .venv/bin/python -m shield.sensors.ebpf.loader                  # needs your password, interactive
.venv/bin/python scripts/measure_resource_budget.py                  # needs bcc_middleware up for the full picture
```

`bcc_middleware` + friends, from `integrity-latest`:
```bash
cd /home/xibalba/Projects/INTEGRITY-LATEST
docker compose up -d --build postgres redis opa oracle-backend bcc-middleware
curl -s http://localhost:8000/health   # {"status":"online",...,"mode":"enforce"} when ready
```
