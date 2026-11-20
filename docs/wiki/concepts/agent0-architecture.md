---
title: Agent0 Architecture & A2A Security Mesh
category: concepts
tags: [agent0, erc8004, a2a, did, identity, passports]
status: active
last_updated: 2026-11-20
---

# Agent0 Architecture & A2A Security Mesh

Xibalba Shield integrates the three-tier modular Agent0 / ERC-8004 Public Passport standard across its defense fleet. This provides cryptographic agent identity, mutual Decentralized Identifier (DID) authentication, policy confinement, and verifiable Agent-to-Agent (A2A) message exchange.

## Token Roster & Identity Registry

Shield defines and queries an on-chain / testnet registry anchored to Base Sepolia:

| Agent Identifier | Role | Token ID | Model | DID | Cortex Scope |
|---|---|---|---|---|---|
| `shield.local` | Local Edge Daemon | #4 | `jev-fast-classifier` | `did:integrity:68fed1331613937555a59398223e8e87520a87dd0305aac4fd7ecdc32a14a861` | `agent:shield.local` |
| `shield.cloud` | Fleet Defense Coordinator | #5 | `hermes-3-70b` | `did:integrity:2ea17967f7a65589d570ca7e800844701fb36e6aa7374243e8766de8651f6bc4` | `agent:shield.cloud` |
| `xibalba.agy` | Antigravity Orchestrator | #10774 | `gemini-2.5-pro` | `did:integrity:b1a72980e8e45e97c7b92982a89b1963e470b45fa955c9bd245f046e1e32e39a` | `agent:agy` |
| `xibalba.claude` | Claude Code Assistant | #6 | `claude-3-7-sonnet` | `did:integrity:f07438ae1fb67f6ab1a21df87fb4771bead162c502c6e98cfa0bbdd7020a7e75` | `agent:claude` |
| `xibalba.codex` | Autonomous Code Agent | #7 | `codex-v2` | `did:integrity:d73b98dd869948c27c7cc16d53683779a23c46daf3020e221955d67d1a8723c5` | `agent:codex` |

## A2A Mutual Authentication Protocol

Communication between `shield.local` and `shield.cloud` is conducted strictly over RFC 8785 Canonical JSON envelopes:

1. **Mutual DID Handshake**: Each party presents its ERC-8004 token ID and cryptographic Ed25519 DID signature.
2. **Policy Confinement Verification**: The receiving agent verifies that the sender's policy confinement contract (`wallet_confined: true`) and registry reference are active.
3. **Payload Canonicalization**: Inbound intent requests and outbound threat correlation advisories are serialized via RFC 8785, hashed with SHA-256, and verified prior to ingestion.
4. **Super-Cortex Memory Attribution**: All exchanges are ingested into Super-Cortex memory with strict `agent:*` scope isolation, verifiable provenance hashes, and zero leakage of raw unredacted credentials.
