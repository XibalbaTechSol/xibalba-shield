#!/usr/bin/env python3
"""
One-time registration of the Shield exporter's DID with the oracle (spec §14.1,
docs/ENTERPRISE_ADOPTION.md Lever 7's documented remaining step).

Not a compose init container on purpose: `integrity_sdk.registration.register_agent` funds a
fresh EVM wallet from `FUNDER_PRIVATE_KEY`, deploys/anchors on-chain state, and independently
re-verifies the result against the oracle -- a secret-bearing, non-idempotent-cost operation
that should run once, deliberately, not be retried silently on every `docker compose up`.

`agent_id="xibalba-shield"` must match the `--agent-label` the `shield` compose service's
`shield run` invocation uses (shield/integrity_exporter/exporter.py's default) -- both resolve
through `integrity_sdk.did.load_or_create_did()` to the same on-disk DID slot under
`INTEGRITY_DID_HOME`, so this registers the exporter's *existing* identity, not a fresh one.

Run from inside the running `shield` container so it shares that identity volume and can reach
`bcc-middleware`/`oracle-backend` by compose DNS name with no extra plumbing. Needs both
`FUNDER_PRIVATE_KEY` (funds the agent's new EVM wallet) and `INTEGRITY_WALLET_PASSWORD`
(encrypts/unlocks that wallet's keystore -- the same two env vars `make demo` already requires,
per this repo's own README/CLAUDE.md):

    docker compose exec \\
        -e FUNDER_PRIVATE_KEY=$FUNDER_PRIVATE_KEY \\
        -e INTEGRITY_WALLET_PASSWORD=$INTEGRITY_WALLET_PASSWORD \\
        shield python scripts/register_with_oracle.py

Re-running this script is safe: register_agent's own idempotency check (a live
XibalbaAgentRegistry.resolveDID lookup) short-circuits to the existing on-chain registration
instead of deploying a second SovereignAgent/StateAnchor pair for the same DID.
"""

from __future__ import annotations

import json
import os
import sys

from integrity_sdk.registration import RegistrationError, register_agent

AGENT_ID = "xibalba-shield"


def main() -> int:
    missing = [
        var for var in ("FUNDER_PRIVATE_KEY", "INTEGRITY_WALLET_PASSWORD")
        if not os.getenv(var)
    ]
    if missing:
        print(f"{', '.join(missing)} not set — both are required to fund/unlock the agent's wallet", file=sys.stderr)
        return 1

    try:
        registration = register_agent(
            agent_id=AGENT_ID,
            rpc_url=os.getenv("RPC_URL", "http://host.docker.internal:8545"),
            deployments_file=os.getenv("DEPLOYMENTS_FILE", "/deployments.local.json"),
            oracle_url=os.getenv("ORACLE_URL", "http://oracle-backend:8080"),
        )
    except RegistrationError as exc:
        print(f"registration failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(registration.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
