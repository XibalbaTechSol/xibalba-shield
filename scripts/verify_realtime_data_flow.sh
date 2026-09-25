#!/usr/bin/env bash
set -euo pipefail

# Read-only end-to-end validation for the independent Shield and Cortex paths.
# This script never starts, stops, reloads, kills, or reconfigures a service.
# Run as root when the decision log or service metadata requires it:
#   sudo scripts/verify_realtime_data_flow.sh --duration 60

python_bin=${PYTHON_BIN:-python3}
exec "$python_bin" - "$@" <<'PY'
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def command(*args: str) -> tuple[int, str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, check=False)
    except OSError as exc:
        return 127, str(exc)
    return result.returncode, (result.stdout or result.stderr).strip()


def systemd(unit: str, *properties: str) -> dict[str, str]:
    rc, output = command("systemctl", "show", unit, *sum((["-p", p] for p in properties), []))
    values: dict[str, str] = {p: "" for p in properties}
    if rc != 0:
        values["_error"] = output
        return values
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in values:
            values[key] = value
    return values


def health(url: str) -> dict[str, object]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return {"reachable": True, "status": response.status, "body": response.read(512).decode(errors="replace")}
    except urllib.error.HTTPError as exc:
        # Cortex intentionally protects even its health route.  HTTP 401 proves
        # the listener is alive without requiring a credential in this audit.
        return {"reachable": True, "status": exc.code, "body": exc.read(512).decode(errors="replace")}
    except (OSError, urllib.error.URLError) as exc:
        return {"reachable": False, "status": None, "body": str(exc)}


def shield_sample(path: Path) -> dict[str, object]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        rollups = connection.execute(
            "SELECT COUNT(*), COALESCE(MAX(last_received_at), ''), COALESCE(SUM(observation_count), 0) "
            "FROM decision_observation_rollups"
        ).fetchone()
        devices = connection.execute(
            "SELECT COUNT(*), COALESCE(MAX(last_seen_at), '') FROM devices"
        ).fetchone()
        decisions = connection.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]
        return {
            "rollup_rows": int(rollups[0]),
            "last_observation": rollups[1],
            "observation_total": int(rollups[2]),
            "device_rows": int(devices[0]),
            "last_device_seen": devices[1],
            "decision_rows": int(decisions),
            "mtime": path.stat().st_mtime,
        }
    finally:
        connection.close()


def outbox_sample(path: Path) -> dict[str, object]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        row = connection.execute(
            "SELECT COUNT(*), COALESCE(SUM(status='pending'), 0), "
            "COALESCE(SUM(sent_at IS NOT NULL), 0), COALESCE(MAX(created_at), 0), "
            "COALESCE(MAX(sent_at), 0) FROM cortex_outbox"
        ).fetchone()
        return {
            "rows": int(row[0]),
            "pending": int(row[1]),
            "sent": int(row[2]),
            "latest_created": float(row[3]),
            "latest_sent": float(row[4]),
            "mtime": path.stat().st_mtime,
        }
    finally:
        connection.close()


def cortex_sample(path: Path) -> dict[str, object]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        result: dict[str, object] = {"mtime": path.stat().st_mtime}
        for table, timestamp in (("otel_events", "created_at"), ("memories", "created_at"), ("sources", "created_at")):
            result[f"{table}_rows"] = int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            result[f"{table}_latest"] = connection.execute(
                f"SELECT COALESCE(MAX({timestamp}), '') FROM {table}"
            ).fetchone()[0]
        return result
    finally:
        connection.close()


def process_stats(pids: list[int]) -> dict[str, object]:
    if not pids:
        return {}
    wanted = ",".join(str(pid) for pid in pids)
    rc, output = command("ps", "-p", wanted, "-o", "pid=,stat=,%cpu=,%mem=,rss=,etime=,cmd=")
    if rc != 0:
        return {"error": output}
    return {"rows": output.splitlines()}


def listener_pids(port: int) -> list[int]:
    rc, output = command("ss", "-lntp")
    if rc != 0:
        return []
    pids: set[int] = set()
    for line in output.splitlines():
        if not re.search(rf":{port}\b", line):
            continue
        pids.update(int(value) for value in re.findall(r"pid=(\d+)", line))
    return sorted(pids)


def emit(kind: str, message: str, failures: list[str]) -> None:
    print(f"{kind} {message}")
    if kind == "FAIL":
        failures.append(message)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=float, default=30, help="sampling window in seconds (default: 30)")
    parser.add_argument("--interval", type=float, default=5, help="sampling interval in seconds (default: 5)")
    parser.add_argument("--shield-db", type=Path, default=Path("/home/xibalba/.xibalba-shield/backend.sqlite3"))
    parser.add_argument("--cortex-db", type=Path, default=Path("/home/xibalba/.hermes/xibalba-cortex-shield/graph-memory.sqlite3"))
    parser.add_argument("--outbox-db", type=Path, default=Path("/var/lib/xibalba-shield/cortex/outbox.sqlite3"))
    parser.add_argument("--json", action="store_true", help="also emit the collected samples as JSON")
    args = parser.parse_args()

    failures: list[str] = []
    if args.duration <= 0 or args.interval <= 0:
        parser.error("--duration and --interval must be positive")
    if not args.shield_db.is_file() or not args.outbox_db.is_file() or not args.cortex_db.is_file():
        emit("FAIL", "one or more expected SQLite databases are missing", failures)
        return 1

    backend = systemd("xibalba-shield-backend.service", "ActiveState", "SubState", "MainPID", "MemoryMax", "CPUQuotaPerSecUSec", "TasksMax", "LimitNOFILE")
    outbox_unit = systemd("xibalba-shield-cortex-outbox.service", "ActiveState", "SubState", "MainPID", "MemoryMax", "CPUQuotaPerSecUSec", "TasksMax", "LimitNOFILE")
    agent = systemd("xibalba-shield.service", "ActiveState", "SubState", "MainPID", "MemoryMax", "CPUQuotaPerSecUSec", "TasksMax", "LimitNOFILE")
    for label, state in (("Shield agent", agent), ("Shield backend", backend), ("Cortex outbox worker", outbox_unit)):
        if state.get("_error"):
            emit("FAIL", f"{label} systemd state unavailable: {state['_error']}", failures)
        else:
            print(f"INFO {label} active={state['ActiveState']} substate={state['SubState']} pid={state['MainPID']}")

    shield_health = health("http://127.0.0.1:8421/api/shield/health")
    cortex_health = health("http://127.0.0.1:8423/health")
    if shield_health["reachable"] and shield_health["status"] == 200:
        emit("PASS", "Shield health endpoint returned HTTP 200", failures)
    else:
        emit("FAIL", f"Shield health unavailable: {shield_health}", failures)
    if cortex_health["reachable"]:
        emit("PASS", f"Cortex listener reachable (HTTP {cortex_health['status']}; authentication boundary intact)", failures)
    else:
        emit("FAIL", f"Cortex listener unavailable: {cortex_health}", failures)

    first = {"shield": shield_sample(args.shield_db), "outbox": outbox_sample(args.outbox_db), "cortex": cortex_sample(args.cortex_db)}
    pids = [int(state["MainPID"]) for state in (agent, backend, outbox_unit) if state.get("MainPID", "").isdigit() and int(state["MainPID"]) > 0]
    pids += listener_pids(8423)
    print(f"INFO sampling {args.duration:g}s at {args.interval:g}s intervals")
    samples = [first]
    started = time.monotonic()
    while time.monotonic() - started < args.duration:
        time.sleep(min(args.interval, max(0.0, args.duration - (time.monotonic() - started))))
        samples.append({"shield": shield_sample(args.shield_db), "outbox": outbox_sample(args.outbox_db), "cortex": cortex_sample(args.cortex_db)})

    last = samples[-1]
    if last["shield"]["observation_total"] > first["shield"]["observation_total"] and last["shield"]["last_observation"] != first["shield"]["last_observation"]:
        emit("PASS", f"Shield observations advanced {last['shield']['observation_total'] - first['shield']['observation_total']} during sample", failures)
    else:
        emit("FAIL", "Shield observation rollups did not advance", failures)

    cortex_advanced = (
        last["outbox"]["sent"] > first["outbox"]["sent"]
        or last["cortex"]["otel_events_latest"] != first["cortex"]["otel_events_latest"]
        or last["cortex"]["memories_latest"] != first["cortex"]["memories_latest"]
    )
    if cortex_advanced:
        emit("PASS", "Cortex acknowledged or persisted newer data during sample", failures)
    else:
        emit("FAIL", "Cortex did not acknowledge or persist newer data during sample", failures)

    if last["outbox"]["pending"] == 0:
        emit("PASS", "Cortex outbox has no pending records", failures)
    else:
        emit("FAIL", f"Cortex outbox has {last['outbox']['pending']} pending records", failures)

    for label, state in (("Shield agent", agent), ("Cortex outbox worker", outbox_unit)):
        if state.get("ActiveState") == "active" and state.get("SubState") == "running":
            emit("PASS", f"{label} is running under systemd", failures)
        else:
            emit("FAIL", f"{label} is not running under systemd ({state.get('ActiveState','unknown')}/{state.get('SubState','unknown')})", failures)

    if backend.get("ActiveState") == "active" and backend.get("SubState") == "running":
        print("INFO Shield backend systemd unit is running")
    else:
        emit("FAIL", f"Shield backend systemd ownership is not healthy ({backend.get('ActiveState','unknown')}/{backend.get('SubState','unknown')})", failures)

    stats = process_stats(sorted(set(pids)))
    print(f"INFO process_stats={json.dumps(stats, sort_keys=True)}")
    if args.json:
        print(json.dumps({"first": first, "last": last, "samples": samples, "process_stats": stats, "failures": failures}, indent=2, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
PY
