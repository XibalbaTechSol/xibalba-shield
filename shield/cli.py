"""
`shield` CLI — spec/xibalba-shield-v1.md §4.6: "a small CLI ... so an admin or pilot customer
can self-inspect what Shield is doing without opening a dashboard." Four commands: `status`/
`events` read the local EventLog (agent_core/eventlog.py) directly, no server; `validate`
loads a policy-rules and/or device-config file through the real shield.config loader and
reports whether it's valid; `run` is the real entry point -- wires a real sensor into a real
EventRouter and actually runs the enforcement loop, the thing every other module in this repo
was built to eventually be part of.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .agent_core.eventlog import EventLog
from .agent_core.registry import AgentRegistry, DeviceContext
from .agent_core.router import EventRouter
from .config import ConfigError, DeviceConfig, load_device_config, load_policy_rules
from .config.hot_reload import PolicyHotReloader
from .policy_engine import PolicyEngine

DEFAULT_LOG_PATH = Path.home() / ".xibalba-shield" / "decisions.jsonl"

_SENSOR_CHOICES = ("process-exec", "file-write", "dev")


class _NullExporter:
    """A real, deliberate no-op -- not a mock of a real exporter. `--no-exporter` is a
    legitimate operational mode (local-only enforcement, no evidence leaves the device),
    matching spec §4.3's requirement that the CORE enforcement loop work with zero cloud
    round-trip. Using this means "no telemetry is being exported," stated as such by the
    CLI (see `_run`'s own printed warning) -- never silently substituted for a real one."""

    def export_event(self, event) -> None:
        pass

    def export_decision(self, decision) -> dict:
        return {"authorized": True}

    def flush(self) -> None:
        pass


def _make_sensor(name: str, device_id: str, tenant_id: str, dev_interval: float):
    if name == "process-exec":
        from .sensors.ebpf.loader import LinuxEbpfSensor

        return LinuxEbpfSensor(device_id=device_id, tenant_id=tenant_id)
    if name == "file-write":
        from .sensors.ebpf.loader import LinuxFileWriteSensor

        return LinuxFileWriteSensor(device_id=device_id, tenant_id=tenant_id)
    if name == "dev":
        from .sensors.dev_generator import DevModeSensor

        return DevModeSensor(device_id=device_id, interval_sec=dev_interval)
    raise ValueError(f"unknown sensor {name!r}")  # unreachable: argparse `choices` already enforces this


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


def _run(args: argparse.Namespace) -> int:
    """The real entry point: wires a real Sensor into a real EventRouter and runs the
    enforcement loop for real. `process-exec`/`file-write` are the two live-VERIFIED eBPF
    sensors (see shield/sensors/ebpf/README.md) -- both need root to construct, and will
    raise a clear PermissionError immediately (not a confusing failure three steps later)
    if this isn't run under sudo. `dev` uses the explicitly-synthetic DevModeSensor, for
    running this loop without root or real kernel events.

    Hot-reload is checked once per handled event, not on a fixed clock -- see
    PolicyHotReloader's own docstring for why mtime-polling was chosen at all; the
    per-event cadence here means reload latency is bounded by "time until the next event,"
    not a guaranteed interval. Stated as a real limitation, not implied as instant."""
    if args.device_config is not None:
        try:
            device_config = load_device_config(args.device_config)
        except ConfigError as exc:
            print(f"shield run: {exc}", file=sys.stderr)
            return 1
    else:
        if not args.device_id:
            print("shield run: --device-id is required unless --device-config is given", file=sys.stderr)
            return 2
        device_config = DeviceConfig(device_id=args.device_id, tenant_id=args.tenant_id or "",
                                     device_role=args.device_role or "",
                                     bcc_middleware_url=args.bcc_middleware_url)

    rules = []
    reloader = None
    if args.rules is not None:
        try:
            rules = load_policy_rules(args.rules)
        except ConfigError as exc:
            print(f"shield run: {exc}", file=sys.stderr)
            return 1
    policy_engine = PolicyEngine(rules=rules)
    if args.rules is not None:
        # PolicyHotReloader has no public "seed with an already-loaded rule set" API, so
        # its own first check_and_reload() will re-parse args.rules once more and find it
        # unchanged from what was just loaded above -- one harmless extra file read+parse
        # at startup, not a correctness issue, and simpler than reaching into its private
        # _last_mtime to skip it.
        reloader = PolicyHotReloader(policy_engine, args.rules)

    if args.no_exporter:
        exporter = _NullExporter()
        print("shield run: --no-exporter set, no evidence will be exported")
    else:
        from .integrity_exporter import IntegrityExporter

        exporter = IntegrityExporter(
            bcc_middleware_url=device_config.bcc_middleware_url,
            oracle_url=args.oracle_url,
            agent_label=args.agent_label,
        )

    device = DeviceContext(device_id=device_config.device_id, tenant_id=device_config.tenant_id,
                           device_role=device_config.device_role)
    registry = AgentRegistry()
    event_log = EventLog(args.log_path)
    router = EventRouter(device=device, registry=registry, policy_engine=policy_engine,
                         exporter=exporter, event_log=event_log)

    try:
        sensor = _make_sensor(args.sensor, device_config.device_id, device_config.tenant_id, args.dev_interval)
    except PermissionError as exc:
        print(f"shield run: {exc}", file=sys.stderr)
        return 1

    print(f"shield run: sensor={args.sensor} device_id={device_config.device_id!r} "
          f"rules={len(rules)} exporter={'none' if args.no_exporter else 'real'}")

    count = 0
    try:
        for event in sensor.events():
            router.handle(event)
            count += 1
            if reloader is not None:
                reloader.check_and_reload()
            if args.max_events and count >= args.max_events:
                break
    except KeyboardInterrupt:
        print(f"\nshield run: interrupted after {count} event(s)")
    finally:
        exporter.flush()

    print(f"shield run: processed {count} event(s), exiting")
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

    p_validate = sub.add_parser("validate", help="validate a policy-rules and/or device-config JSON file")
    p_validate.add_argument("--rules", type=Path, default=None, help="policy rules file (spec §7 shape)")
    p_validate.add_argument("--device-config", type=Path, default=None, help="device/tenant config file")
    p_validate.set_defaults(func=_validate)

    p_run = sub.add_parser("run", help="run the real enforcement loop: sensor -> policy engine -> exporter")
    p_run.add_argument("--sensor", choices=_SENSOR_CHOICES, required=True,
                       help="process-exec/file-write need root (real eBPF); dev needs neither (synthetic)")
    p_run.add_argument("--dev-interval", type=float, default=1.0,
                       help="seconds between synthetic events, --sensor dev only (default: 1.0)")
    p_run.add_argument("--device-config", type=Path, default=None, help="device/tenant config file")
    p_run.add_argument("--device-id", default=None, help="required if --device-config is not given")
    p_run.add_argument("--tenant-id", default=None)
    p_run.add_argument("--device-role", default=None)
    p_run.add_argument("--rules", type=Path, default=None,
                       help="policy rules file; hot-reloaded on change if given")
    p_run.add_argument("--bcc-middleware-url", default="http://localhost:8000")
    p_run.add_argument("--oracle-url", default=None)
    p_run.add_argument("--agent-label", default="xibalba-shield")
    p_run.add_argument("--no-exporter", action="store_true", help="local-only enforcement, export nothing")
    p_run.add_argument("--max-events", type=int, default=None,
                       help="stop after this many events (default: run forever, until Ctrl+C)")
    p_run.set_defaults(func=_run)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
