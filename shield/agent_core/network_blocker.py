"""Narrow nftables adapter for policy-approved destination blocks."""

from __future__ import annotations

import ipaddress
import subprocess
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class NftFlowBlocker:
    """Append one destination/protocol/port rule to a pre-created Shield chain."""

    family: str = "inet"
    table: str = "xibalba_shield"
    chain: str = "output"
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run

    def __call__(self, flow: dict[str, object]) -> str:
        protocol = str(flow.get("protocol", "tcp")).lower()
        if protocol not in {"tcp", "udp"}:
            raise ValueError("flow protocol must be tcp or udp")
        address = ipaddress.ip_address(str(flow.get("dst_ip", "")))
        port = flow.get("dst_port")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError("flow dst_port must be an integer from 1 to 65535")
        address_key = "ip6" if address.version == 6 else "ip"
        argv = [
            "nft", "add", "rule", self.family, self.table, self.chain,
            address_key, "daddr", str(address), protocol, "dport", str(port),
            "counter", "drop", "comment", "xibalba-shield",
        ]
        self.run(argv, check=True, capture_output=True, text=True)
        return "nftables"


__all__ = ["NftFlowBlocker"]
