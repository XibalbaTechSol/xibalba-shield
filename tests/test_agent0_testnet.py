import json
import pytest
from shield.backend.api import (
    _search_agent0_testnet,
    _get_agent0_passport,
    _handle_agent0_talk,
    _enrich_device,
)


def test_agent0_registry_contains_agy_passport():
    passport = _get_agent0_passport(token_id=10774, chain_id=84532)
    assert passport["token_id"] == 10774
    assert passport["chain_id"] == 84532
    assert passport["chain_name"] == "Base Sepolia"
    assert passport["integrity_did"] == "did:integrity:b1a72980e8e45e97c7b92982a89b1963e470b45fa955c9bd245f046e1e32e39a"
    assert passport["actor_wallet"] == "0x388D0180725E0F757C6Ef01ef0474E718faA3776"
    assert passport["claimed"] is True
    assert passport["verified"] is True
    assert passport["wallet_confined"] is True
    assert "0xc37659d4b121edca044d3e3ad7e6cf9f9999c6420845ae8a1439969618d8eec5" in passport["registration_tx"]
    assert "0x0c9c31605660ac30ecc96de8b47f2ff7c267fce0684ee203f3c092f9fc95f9e5" in passport["delegation_tx"]


def test_search_agent0_testnet_filters():
    # All
    all_agents = _search_agent0_testnet()
    assert len(all_agents) >= 4

    # Filter by Base Sepolia
    base_agents = _search_agent0_testnet(chain_id=84532)
    assert any(a["token_id"] == 10774 for a in base_agents)
    assert all(a["chain_id"] == 84532 for a in base_agents)

    # Filter by query
    agy_results = _search_agent0_testnet(query="antigravity")
    assert len(agy_results) == 1
    assert agy_results[0]["token_id"] == 10774

    # Filter by capability
    ebpf_results = _search_agent0_testnet(capability="ebpf_enforcement")
    assert len(ebpf_results) >= 2


def test_handle_agent0_talk_protocol():
    # Test message with context preservation
    turn1 = _handle_agent0_talk(
        message="Audit policy confinement",
        new_conversation=True,
        token_id=10774,
        chain_id=84532,
    )
    assert turn1["status"] == "completed"
    assert turn1["context_id"].startswith("ctx_shield_")
    assert "parts" in turn1
    assert len(turn1["parts"]) == 2
    assert turn1["parts"][0]["kind"] == "text"
    assert "Policy confinement verified active" in turn1["parts"][0]["text"]
    assert turn1["parts"][1]["kind"] == "data"
    data = turn1["parts"][1]["data"]
    assert data["token_id"] == 10774
    assert data["ebpf_redactions"] == 0
    assert data["zero_boundary_escape"] is True

    # Test multi-turn with preserved context_id
    ctx = turn1["context_id"]
    turn2 = _handle_agent0_talk(
        message="Check delegation tx status",
        context_id=ctx,
        new_conversation=False,
        token_id=10774,
        chain_id=84532,
    )
    assert turn2["context_id"] == ctx
    assert "0x0c9c31605660ac30ecc96de8b47f2ff7c267fce0684ee203f3c092f9fc95f9e5" in turn2["parts"][0]["text"]


def test_device_enrichment_includes_agent0_passport():
    dev = {"device_id": "endpoint-1", "tenant_id": "test-tenant"}
    enriched = _enrich_device(dev)
    assert enriched["agent0_token_id"] == 10774
    assert enriched["agent0_chain_id"] == 84532
    assert enriched["actor_wallet"] == "0x388D0180725E0F757C6Ef01ef0474E718faA3776"
    assert "basescan.org" in enriched["agent0_tx_url"]
    assert "basescan.org" in enriched["agent0_delegation_tx_url"]
