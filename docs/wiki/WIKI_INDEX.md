# Xibalba Shield Wiki — Index

> Content catalog. Every page represents something that actually exists in the codebase right
> now — see the schema's "no aspirational content" rule. This is a focused core set covering
> Shield's actual architecture, not an exhaustive catalog — contributions adding more pages are
> welcome.
> Last updated: 2026-08-12 | Total pages: 12 (7 concepts, 2 entities, 2 architecture, 1 query)

## Acronym glossary

- [SLM](concepts/slm-cascade-tiers.md) — Small Language Model (Tier 2 of the cascade)
- [DID](concepts/integrity-exporter.md) — Decentralized Identifier
- [BCC](concepts/integrity-exporter.md) — Behavioral Commitment Chain (defined in `integrity-core`; Shield builds and submits commitments in this shape)
- [OTel](concepts/event-router.md) — OpenTelemetry
- [eBPF](concepts/sensor-model.md) — extended Berkeley Packet Filter (Linux kernel-level sensing)
- [OPA](concepts/policy-engine.md) — Open Policy Agent
- [A2A](concepts/slm-cascade-tiers.md) — Agent-to-Agent (Tier 3 escalation protocol, `[PLANNED]`)

## Concepts

- [Event Router](concepts/event-router.md) — `EventRouter.handle()`'s exact step ordering: Tier 1 → optional Tier 2 → containment (before any network call) → guardrail hooks → two independent export paths → event log
- [Policy Engine](concepts/policy-engine.md) — Tier 1; delegates evaluation to a local OPA sidecar today, **not** the table-driven in-process matcher README.md/CLAUDE.md still describe — documents that drift explicitly
- [Action Broker](concepts/action-broker.md) — real SIGSTOP/SIGCONT/cgroup-v2 containment, SIGKILL only via explicit timeout escalation, wired into `shield run`'s live loop by default
- [Guardrail Hooks](concepts/guardrail-hooks.md) — the six real semantic hook points; explains why `shield run` never wires them in, and how that differs from Action Broker
- [Integrity Exporter](concepts/integrity-exporter.md) — DID + signed BCC commitment + telemetry submission; restored 2026-08-12 after a 2026-08-07 regression
- [SLM Cascade Tiers](concepts/slm-cascade-tiers.md) — the 3-tier Hybrid Cascading Architecture: Tier 1 real, Tier 2 has real inference code now wired via `--slm-backend`, Tier 3 `[PLANNED]`
- [Sensor Model](concepts/sensor-model.md) — the `Sensor` protocol, the synthetic dev sensor, verified/pending Linux eBPF probes, and honest Windows/macOS stubs

## Entities

- [Device Context & Agent Registry](entities/device-context.md) — per-device identity and per-agent registration state the policy engine's evaluation context reads from
- [Event Log](entities/event-log.md) — the local JSONL decision log, optional HMAC hash-chain tamper evidence, `shield verify-log`

## Architecture

- [Ecosystem Role](architecture/ecosystem-role.md) — Shield's role as 🛡️ The Immune System in the three-repository ecosystem
- [Enforcement Pipeline](architecture/enforcement-pipeline.md) — the full sensor-to-evidence flowchart tying Event Router, Policy Engine, Action Broker, and Integrity Exporter together

## Queries

- [Compliance Evidence Trail](queries/compliance-evidence-trail.md) — how a `contain`/`deny` decision becomes auditable evidence today, and what's still open (SIEM destination, OPA policy provenance, export-success dependency)

## Reference

- [index.md](index.md) — the wiki's landing/Home page
- [WIKI_SCHEMA.md](WIKI_SCHEMA.md) — page format, frontmatter, tag taxonomy
- [WIKI_LOG.md](WIKI_LOG.md) — chronological record of every wiki change, append-only
