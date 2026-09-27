# Network Shield Topology and Authority Research

Evidence cutoff: 2026-09-19. This is an observation-only inventory from the Shield host. No
packet capture, network scan, firewall mutation, isolation, DNS change, or controller action was
performed.

## Observed topology

| Surface | Evidence | Classification |
|---|---|---|
| Physical/Wi-Fi uplink | `wlp9s0` UP, `192.168.68.109/24`, default gateway `192.168.68.1` | Verified host-local |
| IPv6 uplink | Link-local address and router advertisement on `wlp9s0` | Verified host-local; upstream topology unknown |
| DNS | systemd-resolved stub on `127.0.0.53`; upstream `1.1.1.1` and `4.4.4.4` | Verified resolver configuration; control authority unknown |
| Docker bridge | `docker0`, `172.17.0.1/16`, down | Verified local virtual network |
| Docker bridge | `br-c9c6fed61582`, `172.18.0.1/16`, down | Verified local virtual network |
| Docker bridge | `br-e6ee3ba2b1f2`, `172.19.0.1/16`, up | Verified local virtual network |
| Endpoint listeners | Shield backend, Cortex APIs, OPA, Caddy, local databases and development services bind primarily to loopback | Verified host-local |
| Gateway/controller | No configured Shield adapter or verified management API found | Unknown/planned |
| Gateway vendor hint | Default gateway neighbor OUI `D8:47:32` is registered to TP-LINK TECHNOLOGIES; model, firmware, management plane, and authorization remain unknown | Partial identification only; not API or authorization evidence |
| DHCP/NAC/switch/Wi-Fi inventory | No Shield integration or authoritative inventory found | Unknown/planned |
| Flow export | No configured NetFlow/IPFIX/sFlow consumer found | Planned |
| DNS policy adapter | No Shield DNS block/sinkhole adapter found | Planned |
| Firewall state | `nft list ruleset` and `iptables-save` require root; no readback was taken in this pass | Blocked pending authorized root read-only probe |
| Packet/flow tools | `tcpdump` exists; `tshark`, `suricata`, `zeek`, and `conntrack` were not found | Tool availability only, not telemetry proof |

## Existing Shield network surfaces

Shield already defines `NetworkFlow`/`NetworkFlowInfo`, a TCP-connect eBPF sensor, synthetic
network events, a readiness-gated `ActionBroker.block_flow()` path, and a narrow nftables
adapter. These are endpoint-local capabilities. They do not prove visibility into the whole
Wi-Fi/LAN, gateway, DNS resolver, managed switch, NAC controller, or cloud egress.

The current network blocker accepts a strictly validated destination/protocol/port flow and is
disabled unless the explicit network capability and fresh runtime readiness proof are present.
No network-wide action will reuse it without adding target scope, protected-network exclusions,
duration/rollback, identity freshness, and blast-radius gates.

## Authority and privacy boundaries

- An endpoint sensor can observe only the endpoint's own process/network activity; it is not a
  network-wide observation point.
- Gateway/firewall/DNS/NAC/controller policy is authoritative only at that enforcement point and
  must be independently authenticated and acknowledged.
- Hermes receives redacted network metadata for correlation and recommendation; it cannot execute
  firewall, router, DNS, NAC, switch, or Wi-Fi commands.
- IPs, MACs, domains, URLs, certificate subjects, usernames, payloads, and customer identifiers
  must be redacted before remote transport. Metadata visibility is not plaintext-content
  visibility; TLS inspection would require separate legal, privacy, key-management, and explicit
  authorization gates.
- No network-wide destructive action is authorized by this inventory.

## Unverified assumptions and next gates

1. Identify the authorized gateway/controller and its supported API without probing or changing
   it.
2. Obtain a disposable lab segment or namespace for adapter tests.
3. Perform an authorized root-only nftables readback and record current management/recovery paths.
4. Select an observation source: endpoint TCP/DNS events, gateway flow export, resolver logs, or
   a controller API; do not combine sources without identity/sequence deduplication.
5. The parallel network event contract and redaction scanner are now implemented at
   `shield/schemas/xibalba.shield.hermes.network_event.schema.json` and
   `shield/network_contract.py`; adapter work remains gated on an authorized disposable lab.
