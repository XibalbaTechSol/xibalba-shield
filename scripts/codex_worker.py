#!/usr/bin/env python3
"""Process Shield advisory event files with Codex in an unprivileged worker."""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

from shield.codex_agent import CodexAdvisoryAgent, CodexAgentError


def process_once(inbox: Path, outbox: Path, *, agent: CodexAdvisoryAgent) -> int:
    processed = 0
    outbox.mkdir(mode=0o750, parents=True, exist_ok=True)
    for source in sorted(inbox.glob("*.json"))[:20]:
        claimed = source.with_suffix(".processing")
        try:
            source.rename(claimed)
        except OSError:
            continue
        try:
            envelope = json.loads(claimed.read_text(encoding="utf-8"))
            result = agent.analyze_event(envelope.get("event", envelope), policy_action=str(envelope.get("policy_action", "")))
            payload = {"source": result.source, "classification": result.classification, "confidence": result.confidence, "rationale": result.rationale, "recommended_test": result.recommended_test, "enforcement": "advisory_only"}
            destination = outbox / f"{claimed.stem}.result.json"
        except (OSError, ValueError, json.JSONDecodeError, CodexAgentError) as exc:
            payload = {"enforcement": "advisory_only", "error": str(exc)}
            destination = outbox / f"{claimed.stem}.error.json"
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, destination)
        claimed.unlink(missing_ok=True)
        processed += 1
    return processed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inbox", type=Path, default=Path("/var/lib/xibalba-shield/codex/inbox"))
    parser.add_argument("--outbox", type=Path, default=Path("/var/lib/xibalba-shield/codex/outbox"))
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if args.interval <= 0:
        parser.error("--interval must be positive")
    args.inbox.mkdir(mode=0o750, parents=True, exist_ok=True)
    agent = CodexAdvisoryAgent()
    while True:
        process_once(args.inbox, args.outbox, agent=agent)
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
