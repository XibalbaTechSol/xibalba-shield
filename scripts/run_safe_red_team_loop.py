#!/usr/bin/env python3
"""Repeat safe live policy fixtures and score the resulting decisions.

This is a development harness only. It routes disposable fixtures through the
installed Shield process, never enables containment, and treats every fixture as
synthetic red-team evidence even though it is persisted for UI inspection.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


EXPECTED = {
    "smb": {
        "smb-contain-shadow-ai-processes": "contain",
        "smb-deny-unregistered-agent-tools": "deny",
        # Router fail-closed behavior converts unresolved escalation to contain.
        "smb-escalate-sensitive-file-write": "contain",
    },
    "professional-services": {
        "ps-deny-unregistered-agents": "deny",
        "ps-escalate-client-data-context": "contain",
    },
    "regulated": {
        "regulated-deny-unregistered-agents": "deny",
        "regulated-deny-phi-context": "deny",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="run_safe_red_team_loop.py")
    parser.add_argument("profile", choices=sorted(EXPECTED))
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--log-path", type=Path, default=Path("/var/log/xibalba-shield/decisions.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("artifacts/safe-red-team-report.json"))
    return parser.parse_args()


def read_rows(path: Path, start_line: int) -> list[dict[str, object]]:
    if not path.exists():
        return []
    rows: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[start_line:]:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("class") == "policy_decision":
            rows.append(row)
    return rows


def main() -> int:
    args = parse_args()
    if os.geteuid() != 0:
        print("Run with sudo.", file=sys.stderr)
        return 1
    if os.environ.get("SHIELD_ENV") != "development":
        print("Refusing to run outside SHIELD_ENV=development", file=sys.stderr)
        return 1
    if args.iterations < 1 or args.iterations > 1000:
        print("--iterations must be between 1 and 1000", file=sys.stderr)
        return 2

    before = sum(1 for _ in args.log_path.open(encoding="utf-8", errors="replace")) if args.log_path.exists() else 0
    runner = Path(__file__).with_name("trigger_live_policy_fixtures.sh")
    env = dict(os.environ)
    env["SHIELD_ENV"] = "development"
    env["SHIELD_DECISION_LOG"] = str(args.log_path)
    fixture_counts = {"smb": 5, "professional-services": 4, "regulated": 4}
    env["SHIELD_FIXTURE_EVENT_COUNT"] = str(fixture_counts[args.profile])

    failures: list[dict[str, object]] = []
    for iteration in range(1, args.iterations + 1):
        result = subprocess.run(["bash", str(runner), args.profile], env=env, text=True, capture_output=True)
        if result.returncode:
            failures.append({"iteration": iteration, "kind": "runner_exit", "returncode": result.returncode, "stderr": result.stderr[-2000:]})
            continue
        print(f"iteration={iteration}/{args.iterations} PASS routed fixtures through EventRouter")

    rows = read_rows(args.log_path, before)
    observed = Counter()
    action_counts = Counter()
    ignored_background_rows = 0
    for row in rows:
        decision = row.get("decision") if isinstance(row.get("decision"), dict) else {}
        rule = row.get("rule") if isinstance(row.get("rule"), dict) else {}
        rule_id = str(rule.get("rule_id", ""))
        action = str(decision.get("action", ""))
        if rule_id not in EXPECTED[args.profile]:
            # The real systemd agent may emit routine observations while the loop
            # runs. They are not fixture misses and must not contaminate scoring.
            ignored_background_rows += 1
            continue
        observed[rule_id] += 1
        action_counts[action] += 1
        expected_action = EXPECTED[args.profile].get(rule_id)
        if action != expected_action:
            failures.append({"kind": "action_mismatch", "rule_id": rule_id, "expected": expected_action, "observed": action})

    expected_minimum = {rule_id: args.iterations for rule_id in EXPECTED[args.profile]}
    missing = {rule_id: count for rule_id, count in expected_minimum.items() if observed[rule_id] < count}
    for rule_id, count in missing.items():
        failures.append({"kind": "missing_decisions", "rule_id": rule_id, "expected_minimum": count, "observed": observed[rule_id]})

    report = {
        "schema": "shield.safe_red_team_report.v1",
        "synthetic": True,
        "profile": args.profile,
        "iterations": args.iterations,
        "decision_rows": len(rows),
        "ignored_background_rows": ignored_background_rows,
        "rule_counts": dict(observed),
        "action_counts": dict(action_counts),
        "expected_actions": EXPECTED[args.profile],
        "failures": failures,
        "status": "pass" if not failures else "attention_required",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "log_path": str(args.log_path),
        "note": "Synthetic disposable fixtures routed through the live EventRouter; not production detection or threat prevalence evidence.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not failures else 3


if __name__ == "__main__":
    raise SystemExit(main())
