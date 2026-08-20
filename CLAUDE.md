# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this
repository.

## What this is

Xibalba Shield — **the AI agent security platform**: the local enforcement and detection layer
that watches what agents actually do on a device and network, and stops or reports on the
dangerous parts in real time. It is a **separate product** from `integrity-core`'s HIPAA
vertical, **Integrity Health** (renamed 2026-08-04 from its own former "Xibalba Shield" name
specifically to remove this ambiguity; the split is recorded in that repo's
`spec/integrity-protocol-v0.4.md` §14.1). "Xibalba Shield" now names only this product. This
repo consumes `integrity-sdk` as a one-way dependency, the same way any third-party agent
runtime would — no privileged API, no special-cased access, and `integrity-core` has zero
dependency back onto this repo in either direction. That boundary is the entire reason the split
exists: a kernel-sensor bug here must never be able to affect AIS computation or Merkle
conventions in the parent protocol.

What makes this a *platform* rather than a static endpoint sensor is the **Hybrid Cascading
Architecture (A2A)** — an escalating cascade of automated judgment applied to agent behavior,
not just a fixed rule table (see Architecture below). The product spans: a Linux-first sensor
layer (process/file/eBPF), a policy engine (deterministic OPA/Rego), guardrail hooks that
intercept an agent's own tool calls, a local SLM tier for semantic judgment beyond static rules,
and (planned) escalation to a cloud frontier model for the hardest cases — plus SIEM/SOAR export
and a backend API for fleet-level visibility. Read `README.md` and `SPECIFICATION.md` for the
full product narrative; this file is the working-code map.

Full technical specification: `spec/xibalba-shield-v1.md` in `integrity-core` (cross-repo
protocol-level spec — read it there, this file assumes it) and this repo's own
`SPECIFICATION.md` / `IMPLEMENTATION_PLAN.md` for Shield-specific design and status.

## Repository layout

```
shield/
├── agent_core/        # DeviceContext, AgentRegistry, EventRouter, EventLog, ActionBroker — spec §4.2
│                        # router.py's handle() calls ActionBroker.contain() FIRST for any
│                        # "contain" decision on a process event (real SIGSTOP, local, no
│                        # network -- the antivirus-speed step), then runs two independent
│                        # best-effort export paths: an OTel span (integrity_sdk.telemetry.tracing)
│                        # and, when configured, integrity_exporter's real signed BCC commitment
│                        # (measured 200-700ms against a live bcc_middleware -- this is why it
│                        # runs after containment, never before)
├── sensors/            # Sensor interface (base.py) + dev_generator.py (real, synthetic) +
│                        # ebpf/ (process/file verified historically; TCP blocked — read ebpf/README.md)
├── policy_engine/      # Tier 1 of the A2A cascade — delegates evaluation to a local OPA
│                        # sidecar (since 2026-08-07, commit f86c0f0) — spec §4.3, §7 —
│                        # condition groups: process/agent/file/flow/context/activity, authored
│                        # as Rego. Rego translations for smb, professional-services, and
│                        # regulated packs exist under policies/rego/. Each vertical must be
│                        # loaded in an isolated OPA package/profile; JSON bundles remain used
│                        # for version/hash pinning, not direct decisions.
├── opa_local.py         # Drives `shield local-run` — a supervised local OPA profile smoke
│                        # loop with Rego bundle allowlisting and SHA-256 identity binding
├── slm_backend.py       # Tier 2 of the A2A cascade — local SLM (Qwen2.5-0.5B) for semantic
│                        # judgment beyond static Rego rules; `--slm-backend {none,simulated,local}`
├── guardrail_hooks/     # all 6 hook points, all real — spec §4.4
├── integrity_exporter/  # Wraps integrity-sdk: real BCC signing + telemetry — spec §4.5
├── integrations/        # SIEM/SOAR export adapters (siem.py)
├── backend/              # FastAPI-style backend API + store — separate `shield-backend` CLI entry
├── config/               # Config loader, hot reload, policy-pack distribution
├── schemas/             # Event classes (§5) + policy rule shape (§7), canonical, no renaming
└── cli.py               # `shield status/events/validate/run/fetch-policy/verify-log/
                         #  siem-export/local-run` — spec §4.6

slm_training/           # Tier-2 SLM training pipeline — app.py, train.py (QLoRA),
                          # generate_dataset.py, dataset.jsonl, models/ (Qwen2.5-0.5B GGUF)
policies/                # defaults/ (JSON: smb, professional-services, regulated) + rego/
packaging/systemd/       # systemd service unit + env example
models/                  # GGUF model weights (Llama-3.2-1B, Qwen2.5-0.5B) + HF cache
assets/                  # brand assets (logos, favicons, OG image)
docs/                    # wiki/ (synced to GitHub wiki), audits/, runbooks/, design/
```

## What's real vs. `[PLANNED]`

Check `README.md`'s status table before assuming any module is further along than it is. The
load-bearing rule this repo inherits from `integrity-core`: **no silent mocks.** If you build
something here that isn't fully working (e.g. extending the eBPF sensor), it must say so
explicitly in its own docstring/README, not imply completeness. `shield/sensors/ebpf/README.md`
is the reference example of how to state that honestly.

## Commands

```bash
uv venv --system-site-packages .venv && uv pip install -e ".[dev]" --python .venv/bin/python
# --system-site-packages: bcc (python3-bpfcc) is a system package, not pip-installable
.venv/bin/python -m pytest        # 138 passed, 7 skipped in the current root-free suite
sudo .venv/bin/python -m pytest tests/test_ebpf_sensor.py -v   # root-gated eBPF tests
shield status                    # local decision-log summary
shield events --recent 20        # recent policy decisions
shield local-run --profile {smb,professional-services,regulated}   # supervised local OPA
                                                                     # profile smoke run
shield-backend                    # separate backend API CLI entry point
python3 scripts/e2e_validate.py    # policy validation, dev sensor loop, BTF checks
```

## Architecture: the Hybrid Cascading Architecture (A2A)

The property that makes Shield a platform rather than a static rule-checker: agent behavior is
judged by an escalating cascade, not one fixed decision path.

- **Tier 1 — deterministic (`policy_engine/`, real, shipping).** OPA/Rego evaluation against
  condition groups (process/agent/file/flow/context/activity). Fast, explainable, the default
  path for anything a static rule can resolve. `shield local-run` exercises this tier end to end
  against a chosen vertical profile.
- **Tier 2 — local SLM (`slm_backend.py`, real demo, shipping).** A local Qwen2.5-0.5B model
  (`--slm-backend local`, or `simulated` for testing without model weights) provides semantic
  judgment for cases Tier 1's static rules can't confidently resolve — e.g. distinguishing a
  legitimate agent tool call from an adversarial one that merely matches a benign-looking
  pattern. `slm_training/` holds the QLoRA fine-tuning pipeline and dataset used to produce this
  model; it is a real, runnable training path, not a mock.
- **Tier 3 — cloud frontier escalation (`[PLANNED]`, no code yet).** The hardest cases would
  escalate to a larger cloud model. Do not imply this tier is implemented in code or docs until
  it exists — follow the "no silent mocks" rule above.

Guardrail hooks (`guardrail_hooks/`) are the interception points where this cascade actually
gets to act on an agent's own tool calls, not just on OS-level process/file/network events —
this is the part of the architecture most specific to *agent* security rather than generic
endpoint security.

## Cross-repo conventions inherited from `integrity-core`

- **BCC commitment shape is frozen** (`docs/INTERFACE_CONTRACT.md` in the parent repo) — this
  repo's `integrity_exporter` must never invent its own commitment fields; it calls
  `integrity_sdk.bcc.build_bcc_commitment` and nothing else builds one. A 2026-08-07 refactor
  briefly deleted this module in favor of OTel-only telemetry, leaving Shield with no path to a
  signed commitment; it was restored 2026-08-12 (`IMPLEMENTATION_PLAN.md`'s former "Known gap —
  2026-08-12" is now closed) and now runs alongside the OTel span, not instead of it — both are
  independent, separately best-effort export paths in `agent_core/router.py`'s `handle()`.
  `IntegrityExporter` is constructed with `background_flush=True` (the SDK default), a deliberate
  change from the pre-deletion version's `background_flush=False` — Shield's decisions fire on a
  real-time enforcement path and must not block on a synchronous telemetry flush.
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
`integrity-core` first if you want that test to actually submit a commitment rather than skip.
