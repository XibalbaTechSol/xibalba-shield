"""
`shield` CLI — spec/xibalba-shield-v1.md §4.6: "a small CLI ... so an admin or pilot customer
can self-inspect what Shield is doing without opening a dashboard." Three commands: `status`/
`events` read the local EventLog (agent_core/eventlog.py) directly, no server; `validate`
loads a policy-rules and/or device-config file through the real shield.config loader
(§4.6's "policies loadable from local files") and reports whether it's valid -- useful before
deploying a bundle, not just after something has already gone wrong with it.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .agent_core.eventlog import EventLog
from .config import ConfigError, load_device_config, load_policy_rules

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


def _validate(args: argparse.Namespace) -> int:
    """Load a policy-rules and/or device-config file through the real loader and report
    the real result -- exit 0/valid only if BOTH given files (whichever were passed) parse
    cleanly, matching the loader's own refuse-the-whole-bundle-loudly posture."""
    ok = True
    if args.rules is not None:
        try:
            rules = load_policy_rules(args.rules)
            print(f"OK   {args.rules}: {len(rules)} rule(s), in order: "
                  f"{', '.join(r.rule_id for r in rules) or '(none)'}")
        except ConfigError as exc:
            print(f"FAIL {args.rules}: {exc}")
            ok = False
    if args.device_config is not None:
        try:
            config = load_device_config(args.device_config)
            print(f"OK   {args.device_config}: device_id={config.device_id!r} "
                  f"tenant_id={config.tenant_id!r} device_role={config.device_role!r}")
        except ConfigError as exc:
            print(f"FAIL {args.device_config}: {exc}")
            ok = False
    if args.rules is None and args.device_config is None:
        print("nothing to validate -- pass --rules and/or --device-config")
        return 2
    return 0 if ok else 1


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

    p_validate = sub.add_parser("validate", help="validate a policy-rules and/or device-config JSON file")
    p_validate.add_argument("--rules", type=Path, default=None, help="policy rules file (spec §7 shape)")
    p_validate.add_argument("--device-config", type=Path, default=None, help="device/tenant config file")
    p_validate.set_defaults(func=_validate)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
