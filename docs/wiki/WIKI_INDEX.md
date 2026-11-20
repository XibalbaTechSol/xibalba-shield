# Xibalba Shield Wiki — Index

> Content catalog. Every page represents something that actually exists in the codebase right
> now — see the schema's "no aspirational content" rule. This is a focused core set covering
> Shield's actual architecture, not an exhaustive catalog — contributions adding more pages are
> welcome.
> Last updated: 2026-11-20 | Total pages: 21 (16 concepts, 2 entities, 2 architecture, 1 query)

## Acronym glossary

- [SLM](concepts/slm-cascade-tiers.md) — Small Language Model (Tier 2 of the cascade)
- [DID](concepts/integrity-exporter.md) — Decentralized Identifier
- [BCC](concepts/integrity-exporter.md) — Behavioral Commitment Chain (defined in `integrity-core`; Shield builds and submits commitments in this shape)
- [OTel](concepts/event-router.md) — OpenTelemetry
- [eBPF](concepts/sensor-model.md) — extended Berkeley Packet Filter (Linux kernel-level sensing)
- [OPA](concepts/policy-engine.md) — Open Policy Agent
- [A2A](concepts/agent0-architecture.md) — Agent-to-Agent communication over canonical RFC 8785 envelopes

## Concepts

- [Agent0 Architecture & A2A Security Mesh](concepts/agent0-architecture.md) — ERC-8004 tokens (#4 shield.local, #5 shield.cloud, #10774 xibalba.agy), mutual DID verification, and policy confinement
- [Kernel Procfs Network Sensor & Real Containment](concepts/procfs-network-sensor.md) — real `/proc/net/tcp` socket telemetry, inode-to-PID correlation, and zero-mock containment via `NftFlowBlocker` & `SIGTERM`
- [Policy Pack Studio & Live OPA Editor](concepts/policy-studio-opa.md) — in-browser Rego editor with live validation, disk persistence, and hot runtime deployment via `PUT /v1/policies/<id>`
- [Configurable Advisory Inference](concepts/advisory-inference.md) — tenant-configurable Jev, local classifier, Lila JSON, and OpenAI-compatible advisory providers with deterministic enforcement authority preserved
- [Event Router](concepts/event-router.md) — `EventRouter.handle()`'s exact step ordering: Tier 1 → optional Tier 2 → containment (before any network call) → guardrail hooks → two independent export paths → event log
- [Policy Engine](concepts/policy-engine.md) — Tier 1; delegates evaluation to a local OPA sidecar with packaged, explicitly selected profile bundles
- [Action Broker](concepts/action-broker.md) — real SIGSTOP/SIGCONT/cgroup-v2 containment, SIGKILL only via explicit timeout escalation, wired into `shield run`'s live loop by default
- [Commissioning Ladder](concepts/commissioning-ladder.md) — the console view that shows, per rung from observe to autonomous, only the evidence the control plane holds; missing measurements read "Not measured", never zero
- [Device App](concepts/device-app.md) — the Tauri tray and desktop app that shows what Shield has frozen on this machine, checked against host OS process state, with dual-agent closed-loop controls; native shell built for Linux and Universal macOS with Playwright E2E verification
- [Guardrail Hooks](concepts/guardrail-hooks.md) — the six real semantic hook points; explains why `shield run` never wires them in, and how that differs from Action Broker
- [Integrity Exporter](concepts/integrity-exporter.md) — DID + signed BCC commitment + telemetry submission; restored 2026-08-12 after a 2026-08-07 regression
- [Shield Detection Quality Metrics](concepts/shield-detection-quality-metrics.md) — Shield ADR, false-positive rate, precision, time-to-contain, and export-success metrics derived from labeled Integrity-backed evidence
- [SLM Cascade Tiers](concepts/slm-cascade-tiers.md) — the 3-tier Hybrid Cascading Architecture: Tier 1 real, Tier 2 has real inference code now wired via `--slm-backend`, Tier 3 `[PLANNED]`
- [Sensor Model](concepts/sensor-model.md) — the `Sensor` protocol, the synthetic dev sensor, verified/pending Linux eBPF probes, and honest Windows/macOS stubs
- [Exporter Remediation](concepts/exporter-remediation.md) — authenticated, bounded `retry`/`flush`/`reconnect` recovery jobs; not a remote shell
- [Xibalba Solutions Enterprise & Commercial Operations](concepts/xibalba-solutions-enterprise.md) — corporate authority, executive contacts, and the 3 commercial software pillars

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
