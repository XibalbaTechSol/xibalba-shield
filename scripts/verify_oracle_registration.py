#!/usr/bin/env python3
"""
Read back the Shield exporter's DID registration from the on-chain registry.

This closes the code path for DID registration/readback. It still requires a reachable RPC
node and deployments file from the Integrity environment; without those, validation should be
reported as blocked rather than faked.
"""

from __future__ import annotations

import os
import sys
import json
import socket
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
SDK_HINTS = [
    Path(os.getenv("INTEGRITY_SDK_PATH", "")) if os.getenv("INTEGRITY_SDK_PATH") else None,
    Path("/home/xibalba/Projects/integrity-core/integrity-sdk"),
]
for sdk_path in SDK_HINTS:
    if sdk_path and (sdk_path / "integrity_sdk" / "chain.py").exists():
        sys.path.insert(0, str(sdk_path))
        break

AGENT_ID = "xibalba-shield"
_ZERO_ADDR = "0x" + "00" * 20


def registry_address(deployments: dict) -> str:
    """The v3 `AgentRegistry` from the deployments file's singletons.

    The v2 `XibalbaAgentRegistry` is deleted in integrity-core slice D5 and is never read here.
    """
    address = (deployments.get("singletons") or {}).get("AgentRegistry")
    if not address:
        raise LookupError("no singletons.AgentRegistry in the deployments file")
    return address


def registry_contract(w3, address: str):
    """Module-level so tests can substitute a fake registry (same seam as integrity-cli's status)."""
    from integrity_sdk import chain

    return chain._contract(w3, "AgentRegistry", address=address)


def read_registration(w3, address: str, agent_did: str) -> dict | None:
    """`AgentRegistry.resolveDID(did)` as a dict, or None when the DID has no on-chain record."""
    pubkey, guardian, actor, domain_id, uri, registered_at, retired_at, proof_kind = (
        registry_contract(w3, address).functions.resolveDID(agent_did).call()
    )
    if not any(pubkey):
        return None
    return {
        "agent_registry": address,
        "pubkey": "0x" + bytes(pubkey).hex(),
        "guardian": guardian,
        "actor": None if not actor or actor.lower() == _ZERO_ADDR else actor,
        "domain_id": "0x" + bytes(domain_id).hex(),
        "uri": uri,
        "registered_at": registered_at,
        "retired_at": retired_at or None,
        "proof_kind": proof_kind,
    }


def _rpc_reachable(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((parsed.hostname, port), timeout=1.5):
            return True
    except OSError:
        return False


def main() -> int:
    rpc_url = os.getenv("RPC_URL", "http://localhost:8545")
    deployments_file = os.getenv("DEPLOYMENTS_FILE", "/home/xibalba/Projects/integrity-core/deployments.local.json")
    if not _rpc_reachable(rpc_url):
        print(f"RPC {rpc_url} is unreachable", file=sys.stderr)
        return 1
    if not Path(deployments_file).exists():
        print(f"deployments file not found: {deployments_file}", file=sys.stderr)
        return 1
    try:
        from integrity_sdk import chain, did

        agent_did, _keypair, _doc = did.load_or_create_did(AGENT_ID)
        w3 = chain.get_w3(rpc_url)
        if not w3.is_connected():
            print(f"RPC {rpc_url} is unreachable", file=sys.stderr)
            return 1
        deployments = chain.load_deployments(deployments_file)
        address = registry_address(deployments)
        resolved = read_registration(w3, address, agent_did)
    except ModuleNotFoundError as exc:
        print(
            f"registration readback dependency missing: {exc.name}; "
            "install the full integrity-sdk runtime before live DID validation",
            file=sys.stderr,
        )
        return 1
    except LookupError as exc:
        print(f"registration readback blocked: {exc.args[0]} ({deployments_file})", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"registration readback failed: {exc}", file=sys.stderr)
        return 1

    if resolved is None:
        print(f"no on-chain AgentRegistry record for {agent_did} (optional in v3)", file=sys.stderr)
        return 1
    if resolved["retired_at"]:
        print(f"on-chain record for {agent_did} is retired at {resolved['retired_at']}", file=sys.stderr)
        return 1

    # `status` is what scripts/pilot_gate_report.py grades (--did-artifact).
    print(json.dumps({"status": "pass", "did": agent_did, "registration": resolved}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
