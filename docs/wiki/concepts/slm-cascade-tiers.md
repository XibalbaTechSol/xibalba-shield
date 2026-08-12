---
title: SLM Cascade Tiers
acronyms: [SLM, A2A]
created: 2026-08-12
updated: 2026-08-12
type: concept
tags: [slm, enforcement]
confidence: high
source_files:
  - shield/agent_core/slm_backend.py
  - shield/agent_core/router.py
  - shield/cli.py
  - slm_training/app.py
  - IMPLEMENTATION_PLAN.md
---

## Table of contents

- [Overview](#overview)
- [Tier 1 — real, wired, deterministic-by-delegation](#tier-1-real-wired-deterministic-by-delegation)
- [Tier 2 — real inference code exists; two disconnected implementations, one now wired](#tier-2-real-inference-code-exists-two-disconnected-implementations-one-now-wired)
- [Tier 3 — [PLANNED], zero code](#tier-3-planned-zero-code)
- [This project cannot build a production Tier-2 model alone](#this-project-cannot-build-a-production-tier-2-model-alone)
- [Related pages](#related-pages)

## Overview

The "Hybrid Cascading Architecture (A2A)" is a 3-tier design: Tier 1 (deterministic policy),
Tier 2 (local small-language-model semantic analysis), Tier 3 (cloud frontier-model escalation
for ambiguous cases). This page states plainly what's real at each tier — the tiers are at very
different stages of completeness, and this repository's own ground rule is that an unbuilt
capability must never be documented as if it were live.

## Tier 1 — real, wired, deterministic-by-delegation

[Policy Engine](policy-engine.md) evaluates every event first. It is real and wired into
[Event Router](event-router.md). Its determinism is *given a loaded OPA policy* — see
policy-engine.md's "Documented drift" section for the important caveat that the OPA sidecar's
actual policy source is undefined in this repository today.

## Tier 2 — real inference code exists; two disconnected implementations, one now wired

There are two distinct things people might mean by "Tier 2," and conflating them has previously
overstated integration in this repo's own `IMPLEMENTATION_PLAN.md`:

**`slm_training/app.py`** — a real, working, standalone Flask demo. It loads Qwen2.5-0.5B via
`llama_cpp.Llama`, requires root, imports the eBPF sensor directly
(`shield.sensors.ebpf.loader.LinuxEbpfSensor`), and performs JSON-schema-constrained
chain-of-thought inference: the model must output `{"reasoning": "...", "action": "ALLOW" |
"CONTAIN" | "ESCALATE"}` via a `response_format` schema. When it decides to contain, it does its
own containment directly — `os.killpg(getpgid(pid), signal.SIGKILL)` — a SIGKILL-only path that
bypasses [Action Broker](action-broker.md) entirely. Nothing under `shield/` imports
`llama_cpp`, `qwen`, or `slm_training`; this demo is standalone and disconnected from the
enforcement path described elsewhere in this wiki.

**`shield/agent_core/slm_backend.py`** — the actual Tier-2 integration point into
[Event Router](event-router.md). It defines:

- `SlmBackend` — a `Protocol` with the same call shape as `PolicyEngine.evaluate(event, ctx) ->
  PolicyDecision`, so a Tier-2 backend is a drop-in escalation path, not a parallel decision
  system.
- `SimulatedSlmBackend` — **not a real model.** A deterministic keyword-pattern mapper mirroring
  the labeled malicious/benign command indicators used to generate
  `slm_training/generate_dataset.py`'s training data. Every decision it returns has `[SIMULATED
  SLM — deterministic pattern match, not a real model]` prefixed onto its `reason` field, so it
  can never be misread as a real model verdict.
- `LocalSlmBackend` — a thin wrapper around real Qwen2.5-0.5B inference. It deliberately does
  *not* import `slm_training.app` (which has import-time side effects: starts a Flask app,
  requires root, calls `os._exit(1)` on failure) — it re-implements only the inference call
  (same system prompt, same JSON-schema `response_format`, same model file) as a library-safe
  path. `llama-cpp-python` is an optional dependency; construction raises a `RuntimeError` with
  an actionable message if it, or the model file, is missing — never a silent fallback to
  another backend.

`EventRouter.handle()` calls the configured `slm_backend.evaluate()` **only** for events Tier 1
already flagged `escalate` — Tier 2 is never the first evaluator an event sees. A revised
`contain` decision from Tier 2 still routes through the real `ActionBroker`, never through
`LocalSlmBackend`'s own logic (it has none) or `slm_training/app.py`'s SIGKILL path.

Wired via CLI:

```bash
shield run --slm-backend {none,simulated,local}   # default: none
```

`none` (the default) preserves prior behavior exactly — no Tier-2 call is ever made, and
`escalate` decisions pass through unchanged.

## Tier 3 — `[PLANNED]`, zero code

There is no Agent-to-Agent (A2A) escalation schema and no cloud-frontier-model client anywhere
in this repository. `IMPLEMENTATION_PLAN.md` lists both as open items: defining a structured A2A
communication schema for local-to-cloud escalations, and implementing the Tier 3 cloud fallback
itself. Nothing at Tier 3 should be represented as built.

## This project cannot build a production Tier-2 model alone

Qwen2.5-0.5B (a community, off-the-shelf small model) is a fill-in, not a purpose-built Xibalba
model. `slm_training/generate_dataset.py`'s synthetic training set is roughly 950 templated rows
from 10 malicious and 8 benign command patterns — real, but well short of the "1,000+ examples,
production-ready" bar `slm_training/README.md` itself names. `slm_training/train.py`'s QLoRA
fine-tune script is documented as unrunnable on the development machine (needs an NVIDIA GPU);
there is no evidence a fine-tune has actually been run. Scaling Tier 2 — more diverse synthetic
data, and the GPU/inference compute to actually train and serve a better model — is an open
community contribution area, not a solo roadmap item. `IMPLEMENTATION_PLAN.md` also flags an
unresolved inconsistency: its narrative names `Llama-3.2-1B-Instruct-Q4_K_M.gguf` as the target
model in one place, while `slm_training/app.py` actually loads `qwen2.5-0.5b-instruct-q4_k_m.gguf`
— not resolved as of this wiki pass, flagged rather than silently picked.

## Related pages

- [Policy Engine](policy-engine.md) — Tier 1
- [Event Router](event-router.md) — the `handle()` step that invokes Tier 2 only on `escalate`
- [Action Broker](action-broker.md) — where a Tier-2 `contain` decision actually gets enforced
