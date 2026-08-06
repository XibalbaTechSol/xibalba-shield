#!/usr/bin/env python3
"""Preflight the live Integrity environment required for Shield DID readback."""

from __future__ import annotations

import importlib.util
import json
import os
import socket
import sys
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SDK = Path("/home/xibalba/Projects/INTEGRITY-LATEST/integrity-sdk")
DEFAULT_DEPLOYMENTS = Path("/home/xibalba/Projects/INTEGRITY-LATEST/deployments.local.json")


def _sdk_path() -> Path | None:
    configured = os.getenv("INTEGRITY_SDK_PATH")
    candidates = [Path(configured)] if configured else []
    candidates.append(DEFAULT_SDK)
    for path in candidates:
        if (path / "integrity_sdk" / "chain.py").exists():
            return path
    return None


def _reachable(url: str) -> bool:
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
    deployments_file = Path(os.getenv("DEPLOYMENTS_FILE", str(DEFAULT_DEPLOYMENTS)))
    sdk_path = _sdk_path()
    if sdk_path is not None:
        sys.path.insert(0, str(sdk_path))

    oracle_url = os.getenv("ORACLE_URL", "")
    checks = {
        "rpc_url": rpc_url,
        "rpc_reachable": _reachable(rpc_url),
        "oracle_url": oracle_url,
        "oracle_reachable": _reachable(oracle_url) if oracle_url else False,
        "deployments_file": str(deployments_file),
        "deployments_file_exists": deployments_file.exists(),
        "integrity_sdk_path": str(sdk_path) if sdk_path else "",
        "integrity_sdk_present": sdk_path is not None,
        "web3_present": importlib.util.find_spec("web3") is not None,
        "eth_account_present": importlib.util.find_spec("eth_account") is not None,
    }
    blockers = [
        name
        for name in ("rpc_reachable", "oracle_reachable", "deployments_file_exists", "integrity_sdk_present", "web3_present", "eth_account_present")
        if not checks[name]
    ]
    status = "ready" if not blockers else "blocked"
    print(json.dumps({"status": status, "blockers": blockers, "checks": checks}, indent=2, sort_keys=True))
    return 0 if status == "ready" else 2


if __name__ == "__main__":
    raise SystemExit(main())
