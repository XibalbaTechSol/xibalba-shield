---
title: Kernel Procfs Network Sensor & Real Containment
category: concepts
tags: [procfs, network, eBPF, nftables, containment, security]
status: active
last_updated: 2026-11-20
---

# Kernel Procfs Network Sensor & Real Containment

Xibalba Shield incorporates a zero-mock network telemetry and containment subsystem centered on real Linux kernel interfaces (`ProcNetTcpSensor` / `RealLinuxNetworkSensor`).

## Telemetry Ingestion via `/proc/net/tcp`

Rather than relying on mocked synthetic fixtures, Shield reads active socket tables directly from the host operating system:
- **IPv4 and IPv6 Tables**: Parsed from `/proc/net/tcp` and `/proc/net/tcp6`.
- **Address & Port Decoding**: Hex-encoded socket representations (`0100007F:1F90` -> `127.0.0.1:8080`) are decoded into high-fidelity `NetworkFlow` records.
- **Socket Inode Resolution**: The socket inode is matched across `/proc/[pid]/fd/*` symlinks (`socket:[<inode>]`) to resolve the exact originating Process ID (PID) without requiring elevated root capabilities.

## Threat Detection Heuristics

Shield monitors active flows against high-risk indicators:
- **Suspicious Outbound C2 Ports**: `SUSPICIOUS_OUTBOUND_PORTS` (`4444`, `1337`, `6667`, `31337`, `8088`, etc.).
- **Unregistered Outbound Sockets**: Outbound connections to unauthorized IP ranges initiated by background worker or agent processes.
- **Domain & Flow Correlation**: Discovered flows are cross-referenced against OPA network policy packs.

## Real Containment Execution

When an adversarial or unauthorized flow is identified, `execute_containment_action()` executes deterministic containment:
1. **Flow Blocking (`block_flow`)**: Utilizes `NftFlowBlocker` to inject nftables / iptables drop rules matching `(src_ip, dst_ip, dst_port, protocol)`.
2. **Process Termination (`kill_process`)**: Issues `os.kill(pid, signal.SIGTERM)` (with graceful escalation to `SIGKILL` if unacknowledged) directly against the offending process.
3. **Audit Ledger & Memory Anchoring**: Records the outcome with SHA-256 containment hash and flushes execution telemetry to Super-Cortex memory and the Integrity Exporter.
