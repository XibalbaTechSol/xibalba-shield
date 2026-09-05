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
import hashlib
import json
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


def _codex_analyze(args: argparse.Namespace) -> int:
    """Run advisory Codex analysis on one JSON event; never changes enforcement state."""
    from .codex_agent import CodexAdvisoryAgent, CodexAgentError

    try:
        raw = args.event_file.read_text(encoding="utf-8") if args.event_file else sys.stdin.read()
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise ValueError("event must be a JSON object")
        result = CodexAdvisoryAgent(timeout=args.timeout).analyze_event(
            event, policy_action=args.policy_action,
        )
    except (OSError, json.JSONDecodeError, ValueError, CodexAgentError) as exc:
        print(f"shield codex-analyze: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "source": result.source,
        "classification": result.classification,
        "confidence": result.confidence,
        "rationale": result.rationale,
        "recommended_test": result.recommended_test,
        "enforcement": "advisory_only",
    }, sort_keys=True))
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
                                     bcc_middleware_url=args.bcc_middleware_url or DeviceConfig.bcc_middleware_url)

    # Exporter URLs: an explicit --bcc-middleware-url/--oracle-url flag always wins (this is
    # what lets docker-compose's shield service point at container-network hostnames); absent
    # that, fall back to the loaded device-config's URLs rather than silently ignoring them.
    # Previously device_config.bcc_middleware_url/oracle_url were loaded but never read again
    # after this point -- a `--device-config` file's URLs had no effect on the exporter at all.
    bcc_middleware_url = args.bcc_middleware_url if args.bcc_middleware_url is not None else device_config.bcc_middleware_url
    oracle_url = args.oracle_url if args.oracle_url is not None else device_config.oracle_url

    rules = []
    policy_version = getattr(args, "policy_version", "")
    policy_hash = getattr(args, "policy_hash", "")
    reloader = None
    if args.rules is None and device_config.tenant_policy_url:
        # An enrolled device owns its policy source.  Fetch once before constructing the
        # engine, then use the same validated local cache for hot reloads.  A configured
        # tenant endpoint that cannot be fetched is a startup failure, not permission to
        # run with an empty policy set.
        policy_cache = Path.home() / ".xibalba-shield" / "policies" / f"{device_config.device_id}.json"
        try:
            fetched = fetch_tenant_policy(device_config=device_config, destination=policy_cache)
            args.rules = fetched.path
            policy_version = fetched.bundle.version
            policy_hash = fetched.bundle.hash
            rules = fetched.bundle.rules
        except ConfigError as exc:
            print(f"shield run: unable to fetch assigned tenant policy: {exc}", file=sys.stderr)
            return 1
    if args.rules is not None:
        try:
            bundle = load_policy_bundle(
                args.rules,
                trusted_signing_keys=device_config.trusted_signing_keys,
                require_signed_policy=device_config.require_signed_policy,
            )
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
    opa_supervisor = None
    if args.opa_command:
        from .opa_supervisor import OpaSupervisor
        opa_supervisor = OpaSupervisor(args.opa_command, args.opa_url)
        try:
            opa_supervisor.start()
        except (OSError, RuntimeError, TimeoutError) as exc:
            print(f"shield run: unable to start supervised OPA: {exc}", file=sys.stderr)
            return 1

    policy_engine = PolicyEngine(opa_url=args.opa_url, policy_version=policy_version, policy_hash=policy_hash)
    from .runtime_status import publish_runtime_status
    publish_runtime_status(
        device_config=device_config,
        policy_status=(reloader.status().__dict__ if reloader else {"healthy": bool(policy_hash), "active_policy_version": policy_version, "active_policy_hash": policy_hash}),
        opa_status=policy_engine.health_status(),
    )
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
            reject_downgrades=device_config.reject_policy_downgrades,
            trusted_signing_keys=device_config.trusted_signing_keys,
            require_signed_policy=device_config.require_signed_policy,
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
            bcc_middleware_url=bcc_middleware_url,
            oracle_url=oracle_url,
            agent_label=args.agent_label,
            chain_id=device_config.chain_id,
            verifying_contract=device_config.verifying_contract,
        )

    # Real OS-level containment, on by default -- this is what makes a "contain" decision
    # actually do something (freeze the offending process) instead of only being logged and
    # exported as evidence after the fact. --no-containment exists for the same reason
    # --no-exporter does: local-only observation/dev use without taking real enforcement
    # action on this machine.
    action_broker = None if args.no_containment else ActionBroker()

    try:
        from .agent_core.slm_backend import build_slm_backend

        slm_backend = build_slm_backend(args.slm_backend)
    except (RuntimeError, ValueError) as exc:
        print(f"shield run: {exc}", file=sys.stderr)
        return 1

    router = EventRouter(device=device, registry=registry, policy_engine=policy_engine,
                         exporter=exporter, action_broker=action_broker, event_log=event_log,
                         slm_backend=slm_backend)

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

    from .watchdog import Watchdog

    watchdog = Watchdog(
        interval=args.watchdog_interval,
        device_config=device_config,
        policy_engine=policy_engine,
        reloader=reloader,
        opa_supervisor=opa_supervisor,
        exporter=exporter,
        sensor=sensor,
    )
    watchdog.start()

    count = 0
    try:
        for event in sensor.events():
            router.handle(event)
            count += 1
            if args.max_events and count >= args.max_events:
                break
    except KeyboardInterrupt:
        print(f"\nshield run: interrupted after {count} event(s)")

    watchdog.stop()
    if opa_supervisor is not None:
        opa_supervisor.stop()

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


def _policy_history(args: argparse.Namespace) -> int:
    from .config.hot_reload import PolicyHotReloader

    reloader = PolicyHotReloader(PolicyEngine(), args.rules, history_dir=args.history_dir)
    entries = reloader.history()
    if not entries:
        print("no retained policy history (no successful reload has been recorded yet, or history is empty)")
        return 0
    for entry in entries:
        print(f"{entry.hash}  policy_version={entry.policy_version or '(none)'}  revision={entry.revision if entry.revision is not None else '(none)'}  loaded_at={entry.loaded_at}")
    return 0


def _policy_rollback(args: argparse.Namespace) -> int:
    from .config.hot_reload import PolicyHotReloader

    reloader = PolicyHotReloader(PolicyEngine(), args.rules, history_dir=args.history_dir)
    if reloader.rollback_to(args.to_hash):
        print(f"OK   rolled back {args.rules} to {args.to_hash}")
        return 0
    print(f"FAIL {args.to_hash} is not in the retained history at {args.history_dir or (Path(args.rules).parent / 'history')}", file=sys.stderr)
    return 1


def _sign_policy(args: argparse.Namespace) -> int:
    import base64

    from integrity_sdk.did import Keypair

    from .config.signing import sign_policy_bundle

    if args.key.exists():
        keypair = Keypair.from_pem(args.key.read_bytes())
    else:
        keypair = Keypair.generate()
        args.key.parent.mkdir(parents=True, exist_ok=True)
        args.key.write_bytes(keypair.private_pem())
        args.key.chmod(0o600)
        print(f"generated a new signing keypair at {args.key} (0600) -- back this up, it cannot be recovered")

    try:
        policy = json.loads(args.input.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"shield sign-policy: cannot read {args.input}: {exc}", file=sys.stderr)
        return 1
    if not isinstance(policy, dict) or "rules" not in policy:
        print(f"shield sign-policy: {args.input} must be a JSON object with a top-level \"rules\" array", file=sys.stderr)
        return 1
    if args.expires_at:
        policy["expires_at"] = args.expires_at

    signed = sign_policy_bundle(policy, keypair)
    args.output.write_text(json.dumps(signed, indent=2))
    print(f"OK   signed {args.input} -> {args.output}  signer_public_key={base64.b64encode(keypair.public_bytes()).decode('ascii')}")
    return 0


def _local_run(args: argparse.Namespace) -> int:
    from .opa_local import selected_profile_metadata, supervised_opa

    try:
        with supervised_opa(args.profile, opa_binary=args.opa_binary, timeout=args.opa_timeout) as opa_url:
            args.opa_url = opa_url
            args.policy_version, args.policy_hash = selected_profile_metadata(args.profile)
            args.device_config = None
            args.rules = None
            args.tenant_id = ""
            args.device_role = ""
            args.bcc_middleware_url = "http://localhost:8000"
            args.oracle_url = None
            args.opa_command = None
            args.agent_label = "xibalba-shield-local"
            args.no_exporter = True
            args.no_containment = True
            args.log_integrity_key = None
            args.slm_backend = "none"
            args.watchdog_interval = 15.0
            return _run(args)
    except (FileNotFoundError, RuntimeError, TimeoutError, OSError) as exc:
        print(f"shield local-run: unable to start selected OPA profile: {exc}", file=sys.stderr)
        return 1


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

    p_codex = sub.add_parser(
        "codex-analyze",
        help="run isolated, advisory Codex analysis for one JSON event; never enforces or broadcasts",
    )
    p_codex.add_argument("--event-file", type=Path, default=None, help="JSON event file; stdin when omitted")
    p_codex.add_argument("--policy-action", default="", help="already-computed Shield action for context")
    p_codex.add_argument("--timeout", type=float, default=30.0)
    p_codex.set_defaults(func=_codex_analyze)

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

    p_policy_history = sub.add_parser("policy-history", help="list retained policy bundle history")
    p_policy_history.add_argument("--rules", type=Path, required=True, help="active policy rules file")
    p_policy_history.add_argument("--history-dir", type=Path, default=None, help="override the default <rules-dir>/history")
    p_policy_history.set_defaults(func=_policy_history)

    p_policy_rollback = sub.add_parser("policy-rollback", help="roll back to a specific retained policy bundle")
    p_policy_rollback.add_argument("--rules", type=Path, required=True, help="active policy rules file to overwrite")
    p_policy_rollback.add_argument("--to-hash", required=True, help="target bundle hash from `shield policy-history` (sha256:... or bare hex)")
    p_policy_rollback.add_argument("--history-dir", type=Path, default=None, help="override the default <rules-dir>/history")
    p_policy_rollback.set_defaults(func=_policy_rollback)

    p_sign_policy = sub.add_parser("sign-policy", help="sign a policy bundle with an Ed25519 keypair")
    p_sign_policy.add_argument("--key", type=Path, required=True, help="Ed25519 private key PEM file; generated if it doesn't exist")
    p_sign_policy.add_argument("--in", dest="input", type=Path, required=True, help="unsigned policy JSON (spec §7 shape)")
    p_sign_policy.add_argument("--out", dest="output", type=Path, required=True, help="destination signed bundle path")
    p_sign_policy.add_argument("--expires-at", default=None, help="optional ISO-8601 expiry, e.g. 2026-12-01T00:00:00Z")
    p_sign_policy.set_defaults(func=_sign_policy)

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
    p_run.add_argument("--bcc-middleware-url", default=None,
                       help="overrides --device-config's bcc_middleware_url if given; "
                            f"falls back to {DeviceConfig.bcc_middleware_url!r} if neither is set")
    p_run.add_argument("--oracle-url", default=None,
                       help="overrides --device-config's oracle_url if given; "
                            "falls back to integrity-sdk's own default if neither is set")
    p_run.add_argument("--opa-command", nargs="+", default=None,
                        help="optional OPA command to supervise; it must listen at --opa-url",
                        metavar="COMMAND")
    p_run.add_argument("--opa-url", default="http://localhost:8181",
                        help="local OPA sidecar the policy engine evaluates rules against "
                             "(PolicyEngine's own default — was previously hardcoded and "
                             "unconfigurable, breaking any deployment where OPA isn't reachable "
                             "at localhost, e.g. a container where it's a separate service)")
    p_run.add_argument("--agent-label", default="xibalba-shield")
    p_run.add_argument("--no-exporter", action="store_true", help="local-only enforcement, export nothing")
    p_run.add_argument("--no-containment", action="store_true",
                       help="observe/decide/log/export only -- never actually freeze a process")
    p_run.add_argument("--slm-backend", choices=("none", "simulated", "local"), default="none",
                       help="Tier-2 escalation backend for Tier-1 'escalate' decisions: 'none' "
                            "(default, unchanged behavior), 'simulated' (deterministic, synthetic "
                            "pattern match -- no model required), 'local' (real Qwen2.5-0.5B "
                            "inference, requires llama-cpp-python + slm_training/models/)")
    p_run.add_argument("--log-integrity-key", type=Path, default=None,
                       help="HMAC key file for tamper-evident decision log entries")
    p_run.add_argument("--max-events", type=int, default=None,
                       help="stop after this many events (default: run forever, until Ctrl+C)")
    p_run.add_argument("--watchdog-interval", type=float, default=15.0,
                       help="seconds between watchdog ticks (hot-reload check, OPA "
                            "restart-if-unhealthy, OPA active health probe, and a status "
                            "publish covering policy/opa/sensors/exporter) -- runs "
                            "independent of event traffic, so an idle or stalled sensor "
                            "stream no longer freezes health reporting")
    p_run.set_defaults(func=_run)

    p_local = sub.add_parser("local-run", help="local smoke loop with a supervised, selected OPA profile")
    p_local.add_argument("--profile", choices=("smb", "professional-services", "regulated"), required=True)
    p_local.add_argument("--sensor", choices=_SENSOR_CHOICES, default="dev")
    p_local.add_argument("--device-id", default="local-smoke")
    p_local.add_argument("--dev-interval", type=float, default=0.0)
    p_local.add_argument("--opa-binary", default="opa")
    p_local.add_argument("--opa-timeout", type=float, default=5.0)
    p_local.add_argument("--max-events", type=int, default=1)
    p_local.add_argument("--log-path", type=Path, default=DEFAULT_LOG_PATH)
    p_local.set_defaults(func=_local_run)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
