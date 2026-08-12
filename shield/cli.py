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

from .agent_core.action_broker import ActionBroker
from .agent_core.eventlog import EventLog
from .agent_core.registry import AgentRegistry, DeviceContext
from .agent_core.router import EventRouter
from .config import ConfigError, DeviceConfig, fetch_tenant_policy, load_device_config, load_policy_bundle
from .config.hot_reload import PolicyHotReloader
from .policy_engine import PolicyEngine

DEFAULT_LOG_PATH = Path.home() / ".xibalba-shield" / "decisions.jsonl"

_SENSOR_CHOICES = ("process-exec", "file-write", "tcp-connect", "dev")





def _make_sensor(
    name: str,
    device_id: str,
    tenant_id: str,
    dev_interval: float,
    sensitive_paths: list[str],
):
    if name == "process-exec":
        from .sensors.ebpf.loader import LinuxEbpfSensor

        return LinuxEbpfSensor(device_id=device_id, tenant_id=tenant_id)
    if name == "file-write":
        from .sensors.ebpf.loader import LinuxFileWriteSensor

        return LinuxFileWriteSensor(
            device_id=device_id,
            tenant_id=tenant_id,
            sensitive_path_globs=sensitive_paths,
        )
    if name == "tcp-connect":
        from .sensors.ebpf.loader import LinuxTcpConnectSensor

        return LinuxTcpConnectSensor(device_id=device_id, tenant_id=tenant_id)
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
        export = row.get("export", {})
        # authorized is None whenever no Integrity Exporter ran at all (no exporter
        # configured, e.g. --no-exporter) -- distinct from a real exporter having run and
        # failed (authorized False). Conflating the two as "failed" misreports a
        # deliberately telemetry-only run as a broken evidence submission.
        if not export.get("attempted"):
            export_status = "not_attempted"
        elif export.get("authorized") is None:
            export_status = "telemetry_only" if export.get("event_exported") else "failed"
        else:
            export_status = "ok" if export.get("authorized") else "failed"
        print(
            f"{row.get('time', '?')}  {row.get('event_ref', {}).get('class', '?'):16} "
            f"action={decision.get('action', '?'):9} rule={rule.get('rule_id', '?')} "
            f"export={export_status}"
        )
    return 0


def _validate(args: argparse.Namespace) -> int:
    """Load a policy-rules and/or device-config file through the real loader and report
    the real result -- exit 0/valid only if BOTH given files (whichever were passed) parse
    cleanly, matching the loader's own refuse-the-whole-bundle-loudly posture."""
    ok = True
    if args.rules is not None:
        try:
            bundle = load_policy_bundle(args.rules)
            rules = bundle.rules
            print(f"OK   {args.rules}: {len(rules)} rule(s), in order: "
                  f"{', '.join(r.rule_id for r in rules) or '(none)'} "
                  f"policy_version={bundle.version or '(none)'} policy_hash={bundle.hash}")
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
    policy_version = ""
    policy_hash = ""
    reloader = None
    if args.rules is not None:
        try:
            bundle = load_policy_bundle(args.rules)
            rules = bundle.rules
            policy_version = bundle.version
            policy_hash = bundle.hash
        except ConfigError as exc:
            print(f"shield run: {exc}", file=sys.stderr)
            return 1
        if device_config.trusted_policy_hashes and policy_hash not in device_config.trusted_policy_hashes:
            print(
                f"shield run: policy bundle {args.rules} hash {policy_hash} is not trusted by device config",
                file=sys.stderr,
            )
            return 1
    policy_engine = PolicyEngine(policy_version=policy_version, policy_hash=policy_hash)
    if args.rules is not None:
        # PolicyHotReloader has no public "seed with an already-loaded rule set" API, so
        # its own first check_and_reload() will re-parse args.rules once more and find it
        # unchanged from what was just loaded above -- one harmless extra file read+parse
        # at startup, not a correctness issue, and simpler than reaching into its private
        # _last_mtime to skip it.
        reloader = PolicyHotReloader(
            policy_engine,
            args.rules,
            trusted_policy_hashes=device_config.trusted_policy_hashes,
        )

    device = DeviceContext(device_id=device_config.device_id, tenant_id=device_config.tenant_id,
                           device_role=device_config.device_role)
    registry = AgentRegistry()
    event_log = EventLog(args.log_path, integrity_key_path=args.log_integrity_key)

    # Build a real Integrity Exporter unless the operator explicitly opted out with
    # --no-exporter. Imported lazily so commands that don't run the enforcement loop
    # (status/events/validate/etc.) never pull in integrity-sdk's heavier dependencies.
    exporter = None
    if not args.no_exporter:
        from .integrity_exporter import IntegrityExporter

        exporter = IntegrityExporter(
            bcc_middleware_url=args.bcc_middleware_url,
            oracle_url=args.oracle_url,
            agent_label=args.agent_label,
        )

    # Real OS-level containment, on by default -- this is what makes a "contain" decision
    # actually do something (freeze the offending process) instead of only being logged and
    # exported as evidence after the fact. --no-containment exists for the same reason
    # --no-exporter does: local-only observation/dev use without taking real enforcement
    # action on this machine.
    action_broker = None if args.no_containment else ActionBroker()

    router = EventRouter(device=device, registry=registry, policy_engine=policy_engine,
                         exporter=exporter, action_broker=action_broker, event_log=event_log)

    try:
        sensor = _make_sensor(
            args.sensor,
            device_config.device_id,
            device_config.tenant_id,
            args.dev_interval,
            device_config.sensitive_paths,
        )
    except PermissionError as exc:
        print(f"shield run: {exc}", file=sys.stderr)
        return 1

    print(f"shield run: sensor={args.sensor} device_id={device_config.device_id!r} "
          f"rules={len(rules)} policy_hash={policy_hash or '(none)'}")

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

    print(f"shield run: processed {count} event(s), exiting")
    return 0


def _fetch_policy(args: argparse.Namespace) -> int:
    try:
        device_config = load_device_config(args.device_config)
        result = fetch_tenant_policy(
            device_config=device_config,
            destination=args.output,
            timeout_sec=args.timeout,
        )
    except ConfigError as exc:
        print(f"shield fetch-policy: {exc}", file=sys.stderr)
        return 1
    print(
        f"OK   fetched {len(result.bundle.rules)} rule(s) from {result.source_url} "
        f"to {result.path} policy_version={result.bundle.version or '(none)'} "
        f"policy_hash={result.bundle.hash}"
    )
    return 0


def _verify_log(args: argparse.Namespace) -> int:
    result = EventLog(args.log_path, integrity_key_path=args.integrity_key).verify()
    if result.get("ok"):
        print(f"OK   verified {result.get('checked', 0)} decision log entries")
        if result.get("last_hash"):
            print(f"     last_hash={result['last_hash']}")
        return 0
    print(
        f"FAIL decision log integrity: line={result.get('line', '?')} "
        f"checked={result.get('checked', 0)} reason={result.get('reason', 'unknown')}",
        file=sys.stderr,
    )
    return 1


def _siem_export(args: argparse.Namespace) -> int:
    from .integrations.siem import export_decision_log_to_jsonl, post_decision_log_to_webhook

    if bool(args.output) == bool(args.webhook_url):
        print("shield siem-export: pass exactly one of --output or --webhook-url", file=sys.stderr)
        return 2
    if args.webhook_url:
        result = post_decision_log_to_webhook(args.log_path, args.webhook_url, timeout_sec=args.timeout)
    else:
        result = export_decision_log_to_jsonl(args.log_path, args.output, profile=args.profile)
    print(f"OK   siem export: exported={result.exported} failed={result.failed}")
    return 0 if result.failed == 0 else 1


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

    p_fetch = sub.add_parser("fetch-policy", help="fetch and validate a tenant policy bundle")
    p_fetch.add_argument("--device-config", type=Path, required=True, help="device config with tenant_policy_url")
    p_fetch.add_argument("--output", type=Path, required=True, help="destination policy bundle path")
    p_fetch.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds")
    p_fetch.set_defaults(func=_fetch_policy)

    p_verify_log = sub.add_parser("verify-log", help="verify a tamper-evident decision log hash chain")
    p_verify_log.add_argument("--integrity-key", type=Path, required=True, help="HMAC key file used when writing the log")
    p_verify_log.set_defaults(func=_verify_log)

    p_siem = sub.add_parser("siem-export", help="export decision logs to SIEM/SOAR receivers")
    p_siem.add_argument("--output", type=Path, default=None, help="write normalized JSONL to this path")
    p_siem.add_argument("--webhook-url", default=None, help="POST each decision to this webhook")
    p_siem.add_argument("--profile", choices=("generic", "elastic", "splunk"), default="generic")
    p_siem.add_argument("--timeout", type=float, default=10.0, help="webhook timeout in seconds")
    p_siem.set_defaults(func=_siem_export)

    p_run = sub.add_parser("run", help="run the real enforcement loop: sensor -> policy engine -> containment -> exporter")
    p_run.add_argument("--sensor", choices=_SENSOR_CHOICES, required=True,
                       help="process-exec/file-write/tcp-connect need root (real eBPF); dev needs neither (synthetic)")
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
    p_run.add_argument("--no-containment", action="store_true",
                       help="observe/decide/log/export only -- never actually freeze a process")
    p_run.add_argument("--log-integrity-key", type=Path, default=None,
                       help="HMAC key file for tamper-evident decision log entries")
    p_run.add_argument("--max-events", type=int, default=None,
                       help="stop after this many events (default: run forever, until Ctrl+C)")
    p_run.set_defaults(func=_run)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
