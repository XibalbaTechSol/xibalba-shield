# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this
repository.

## What this is

Xibalba Shield — a device/network-security endpoint agent, and a **separate product** from
`integrity-latest`'s HIPAA vertical (also historically called "Xibalba Shield"; the split is
recorded in that repo's `spec/integrity-protocol-v0.4.md` §14.1). This repo consumes
`integrity-sdk` as a one-way dependency, the same way any third-party agent runtime would — no
privileged API, no special-cased access, and `integrity-latest` has zero dependency back onto
this repo in either direction. That boundary is the entire reason the split exists: a
kernel-sensor bug here must never be able to affect AIS computation or Merkle conventions in the
parent protocol.

Full technical specification: `spec/xibalba-shield-v1.md` in `integrity-latest` (not duplicated
here — read it there, this file assumes it).

## Repository layout

```
shield/
├── agent_core/        # DeviceContext, AgentRegistry, EventRouter, EventLog — spec §4.2
├── sensors/            # Sensor interface (base.py) + dev_generator.py (real, synthetic) +
│                        # ebpf/ (real code, UNVERIFIED — read ebpf/README.md before touching it)
├── policy_engine/      # Table-driven rule evaluator — spec §4.3, §7 — condition groups:
│                        # process/agent/file/flow/context/activity
├── guardrail_hooks/     # all 6 hook points, all real — spec §4.4
├── integrity_exporter/  # Wraps integrity-sdk: BCC signing + telemetry — spec §4.5
├── schemas/             # Event classes (§5) + policy rule shape (§7), canonical, no renaming
└── cli.py               # `shield status` / `shield events --recent` — spec §4.6
```

## What's real vs. `[PLANNED]`

Check `README.md`'s status table before assuming any module is further along than it is. The
load-bearing rule this repo inherits from `integrity-latest`: **no silent mocks.** If you build
something here that isn't fully working (e.g. extending the eBPF sensor), it must say so
explicitly in its own docstring/README, not imply completeness. `shield/sensors/ebpf/README.md`
is the reference example of how to state that honestly.

## Commands

```bash
uv venv --system-site-packages .venv && uv pip install -e ".[dev]" --python .venv/bin/python
# --system-site-packages: bcc (python3-bpfcc) is a system package, not pip-installable
.venv/bin/python -m pytest        # 18 pass, 3 skip: 2 need root (real eBPF load/attach — see
                                   # shield/sensors/ebpf/README.md), 1 self-skips if
                                   # bcc_middleware isn't reachable, rather than failing the suite
sudo .venv/bin/python -m pytest tests/test_ebpf_sensor.py -v   # the 2 root-gated eBPF tests
shield status                    # local decision-log summary
shield events --recent 20        # recent policy decisions
```

## Cross-repo conventions inherited from `integrity-latest`

- **BCC commitment shape is frozen** (`docs/INTERFACE_CONTRACT.md` in the parent repo) — this
  repo's `integrity_exporter` must never invent its own commitment fields; it calls
  `integrity_sdk.bcc.build_bcc_commitment` and nothing else builds one.
- **AIS is computed in exactly one place**, `integrity-oracle/scoring-core` in the parent repo.
  Nothing in this repo may compute or approximate an AIS delta itself — `schemas/policy_rule.py`'s
  `ais_impact` field is a *hint* for a future oracle-side mapping layer, never a direct score
  write from here.
- **Fail-open/fail-closed postures are stated explicitly per module**, matching
  `bcc_middleware`'s own documented pattern in the parent repo (see that repo's `CLAUDE.md` on
  its intercept pipeline) — don't add a new failure path without stating which way it fails and
  why, in the module's own docstring.

## Testing conventions

Unit tests (`policy_engine`, `agent_core`) are pure logic, no network, no fixtures needed.
The one integration test exercises `IntegrityExporter` against a real local `bcc_middleware` —
run `docker compose up -d bcc-middleware` (or the equivalent local dev stack) from
`integrity-latest` first if you want that test to actually submit a commitment rather than skip.
