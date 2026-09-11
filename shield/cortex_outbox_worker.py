"""Durable Shield -> Cortex outbox delivery worker.

The watchdog may flush opportunistically, but this process is the independent retry boundary:
it keeps delivery alive when no new device event arrives and exposes dead-letter/loss counters
through the same SQLite outbox used by the provider.
"""

from __future__ import annotations

import argparse
import time

from .agent_core.cortex_memory import CortexMemoryProvider


def main() -> None:
    parser = argparse.ArgumentParser(prog="shield-cortex-outbox")
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--agent-id", default=None)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--batch-size", type=int, default=20)
    args = parser.parse_args()
    provider = CortexMemoryProvider.from_environment(device_id=args.device_id, agent_id=args.agent_id)
    if provider is None:
        raise SystemExit("XIBALBA_CORTEX_URL, XIBALBA_CORTEX_TOKEN, and XIBALBA_AGENT_ID are required")
    while True:
        provider.flush(limit=max(1, min(args.batch_size, 1000)))
        if args.once:
            return
        time.sleep(max(0.25, args.interval))


if __name__ == "__main__":
    main()
