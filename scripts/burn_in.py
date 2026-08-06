#!/usr/bin/env python3
"""
Root-free burn-in harness for Shield's enforcement/export loop.

This uses the dev sensor by default so it can run in CI and on laptops. For customer pilots,
run it beside the Linux eBPF service and SIEM/Integrity exporters, then compare this local
resource/export baseline with host telemetry over multi-day windows.
"""

from __future__ import annotations

import argparse
import json
import resource
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from shield.agent_core.eventlog import EventLog
from shield.agent_core.registry import AgentRegistry, DeviceContext
from shield.agent_core.router import EventRouter
from shield.cli import _NullExporter
from shield.config import load_policy_bundle
from shield.policy_engine import PolicyEngine
from shield.sensors.dev_generator import DevModeSensor


def _load_false_positive_stats(path: Path | None) -> dict[str, object]:
    if path is None:
        return {
            "rate": None,
            "reviewed": 0,
            "false_positive_count": 0,
            "note": "requires operator-labeled pilot review data; this harness records candidate decision volume only",
        }
    reviewed = 0
    false_positive_count = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if "false_positive" not in row:
            continue
        reviewed += 1
        false_positive_count += int(bool(row["false_positive"]))
    return {
        "rate": round(false_positive_count / reviewed, 6) if reviewed else None,
        "reviewed": reviewed,
        "false_positive_count": false_positive_count,
        "note": "operator-labeled review file supplied" if reviewed else "no false_positive labels found in review file",
    }


def main() -> int:
    parser = argparse.ArgumentParser(prog="burn_in.py")
    parser.add_argument("--duration-sec", type=float, default=60.0)
    parser.add_argument("--max-events", type=int, default=1000)
    parser.add_argument("--rules", type=Path, default=Path("policies/defaults/smb.json"))
    parser.add_argument("--output", type=Path, default=Path("artifacts/burn-in.json"))
    parser.add_argument("--log-path", type=Path, default=Path("artifacts/burn-in-decisions.jsonl"))
    parser.add_argument(
        "--false-positive-labels",
        type=Path,
        default=None,
        help="optional JSONL operator review file with false_positive booleans",
    )
    args = parser.parse_args()

    bundle = load_policy_bundle(args.rules)
    router = EventRouter(
        device=DeviceContext(device_id="burn-in-dev", tenant_id="burn-in", device_role="workstation"),
        registry=AgentRegistry(),
        policy_engine=PolicyEngine(rules=bundle.rules, policy_version=bundle.version, policy_hash=bundle.hash),
        exporter=_NullExporter(),
        event_log=EventLog(args.log_path),
    )
    sensor = DevModeSensor(device_id="burn-in-dev", interval_sec=0)
    started = time.monotonic()
    decisions: dict[str, int] = {}
    processed = 0
    for event in sensor.events():
        decision = router.handle(event)
        decisions[decision.decision.action] = decisions.get(decision.decision.action, 0) + 1
        processed += 1
        if processed >= args.max_events or time.monotonic() - started >= args.duration_sec:
            break

    elapsed = time.monotonic() - started
    usage = resource.getrusage(resource.RUSAGE_SELF)
    false_positive_stats = _load_false_positive_stats(args.false_positive_labels)
    report = {
        "duration_sec": round(elapsed, 3),
        "events": processed,
        "events_per_sec": round(processed / elapsed, 2) if elapsed else processed,
        "decisions": decisions,
        "max_rss_kb": usage.ru_maxrss,
        "policy_hash": bundle.hash,
        "policy_version": bundle.version,
        "false_positive_rate": false_positive_stats["rate"],
        "false_positive_reviewed": false_positive_stats["reviewed"],
        "false_positive_count": false_positive_stats["false_positive_count"],
        "false_positive_note": false_positive_stats["note"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
