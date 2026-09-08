from __future__ import annotations

import pytest

from shield.agent_core.network_blocker import NftFlowBlocker


def test_nft_blocker_uses_argv_and_scopes_destination():
    calls = []
    blocker = NftFlowBlocker(run=lambda argv, **kwargs: calls.append((argv, kwargs)))
    assert blocker({"protocol": "tcp", "dst_ip": "192.0.2.8", "dst_port": 443}) == "nftables"
    argv, kwargs = calls[0]
    assert argv == ["nft", "add", "rule", "inet", "xibalba_shield", "output", "ip", "daddr", "192.0.2.8", "tcp", "dport", "443", "counter", "drop", "comment", "xibalba-shield"]
    assert kwargs == {"check": True, "capture_output": True, "text": True}


@pytest.mark.parametrize("flow", [
    {"protocol": "icmp", "dst_ip": "192.0.2.8", "dst_port": 443},
    {"protocol": "tcp", "dst_ip": "not-an-ip", "dst_port": 443},
    {"protocol": "tcp", "dst_ip": "192.0.2.8", "dst_port": 0},
])
def test_nft_blocker_rejects_unscoped_or_invalid_flow(flow):
    with pytest.raises(ValueError):
        NftFlowBlocker(run=lambda *_args, **_kwargs: None)(flow)
