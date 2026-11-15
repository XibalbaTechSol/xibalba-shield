#!/usr/bin/env python3
"""
Register the Shield exporter's DID with the Integrity Oracle, off-chain (gas-free).

`shield run` does this automatically on first start when ORACLE_URL is set
(`IntegrityExporter.register_offchain_once`); this script is the manual equivalent for an
operator who wants to register (or confirm registration) without starting the sensor.

It signs a challenge with the exporter's existing Ed25519 key and POSTs it to the Oracle's
`/v1/agent/register/offchain`. No chain state is touched: no funder key, no wallet password,
no contract deployment. Registration is idempotent, so re-running is safe.

`--agent-id` must match the `--agent-label` `shield run` uses (default "xibalba-shield"); both
resolve through `integrity_sdk.did.load_or_create_did()` to the same on-disk DID slot under
`INTEGRITY_DID_HOME`, so this registers the exporter's *existing* identity, not a fresh one.

    python scripts/register_with_oracle.py --oracle-url https://oracle.example
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

AGENT_ID = "xibalba-shield"
# Oracle-local XNS handle already claimed for this device's Shield agent.
XNS_HANDLE = "xibalba.shield"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scripts/register_with_oracle.py")
    parser.add_argument("--agent-id", default=AGENT_ID)
    parser.add_argument("--oracle-url", default=os.getenv("ORACLE_URL", "http://oracle-backend:8080"))
    parser.add_argument(
        "--handle",
        default=os.getenv("SHIELD_XNS_HANDLE", XNS_HANDLE),
        help="unique Oracle-local XNS handle for this agent",
    )
    args = parser.parse_args(argv)

    try:
        from integrity_sdk import did as sdk_did
        from integrity_sdk.registration_offchain import OffchainRegistrationError, register_offchain
    except ImportError as exc:
        print(
            f"integrity-sdk lacks registration_offchain ({exc}); upgrade integrity-sdk",
            file=sys.stderr,
        )
        return 1

    did, keypair, doc = sdk_did.load_or_create_did(args.agent_id)
    try:
        registration = register_offchain(
            args.oracle_url, did, keypair, handle=args.handle, did_document=doc
        )
    except OffchainRegistrationError as exc:
        print(f"registration failed: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"invalid registration arguments: {exc}", file=sys.stderr)
        return 2

    print(json.dumps({
        "did": did,
        "agent_id": registration.agent_id,
        "verification_tier": registration.verification_tier,
        "outcome": registration.outcome,
        "handle": registration.handle,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
