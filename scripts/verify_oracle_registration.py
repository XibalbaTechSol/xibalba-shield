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
        registry_address = deployments["singletons"]["XibalbaAgentRegistry"]
        resolved = chain.resolve_did(w3, registry_address, agent_did)
    except ModuleNotFoundError as exc:
        print(
            f"registration readback dependency missing: {exc.name}; "
            "install the full integrity-sdk runtime before live DID validation",
            file=sys.stderr,
        )
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"registration readback failed: {exc}", file=sys.stderr)
        return 1

    if resolved is None:
        print(f"DID is not registered: {agent_did}", file=sys.stderr)
        return 1

    print(json.dumps({"did": agent_did, "registration": resolved.__dict__}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
