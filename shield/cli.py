"""
`shield` CLI — spec/xibalba-shield-v1.md §4.6: "a small CLI ... so an admin or pilot customer
can self-inspect what Shield is doing without opening a dashboard." Deliberately minimal —
two commands, both reading the local EventLog (agent_core/eventlog.py) directly, no server.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .agent_core.eventlog import EventLog

DEFAULT_LOG_PATH = Path.home() / ".xibalba-shield" / "decisions.jsonl"


def _status(args: argparse.Namespace) -> int:
    log = EventLog(args.log_path)
    total = log.count()
    print(f"xibalba-shield status")
    print(f"  decision log: {args.log_path}")
    print(f"  decisions recorded: {total}")
    if total == 0:
        print("  (no decisions yet — run a sensor loop, e.g. shield.sensors.dev_generator, "
              "and route events through an EventRouter to populate this)")
    return 0


def _events(args: argparse.Namespace) -> int:
    log = EventLog(args.log_path)
    rows = log.recent(args.recent)
    if not rows:
        print("no decisions recorded yet")
        return 0
    for row in rows:
        decision = row.get("decision", {})
        rule = row.get("rule", {})
        print(
            f"{row.get('time', '?')}  {row.get('event_ref', {}).get('class', '?'):16} "
            f"action={decision.get('action', '?'):9} rule={rule.get('rule_id', '?')}"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shield")
    parser.add_argument(
        "--log-path", type=Path, default=DEFAULT_LOG_PATH,
        help=f"decision log path (default: {DEFAULT_LOG_PATH})",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_status = sub.add_parser("status", help="show a summary of what Shield has observed")
    p_status.set_defaults(func=_status)

    p_events = sub.add_parser("events", help="show recent policy decisions")
    p_events.add_argument("--recent", type=int, default=20)
    p_events.set_defaults(func=_events)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
