"""
Tests for `shield validate` and `shield run` (shield/cli.py) -- exercises the real argparse
wiring, the real shield.config loader, and (for `run`) the real EventRouter/PolicyEngine/
EventLog end to end, not just each piece in isolation. Real temp files, real `main()`
invocation, real captured stdout/exit code and log contents. Every `run` invocation passes
`--max-events` and `--sensor dev` -- the only sensor that needs neither root nor a real
kernel event to produce real, policy-evaluated `PolicyDecision`s.
"""

from __future__ import annotations

import json

from shield.agent_core.eventlog import EventLog
from shield.cli import main


def _write(path, obj):
    path.write_text(json.dumps(obj))
    return path


def test_validate_valid_rules_file_exits_zero(tmp_path, capsys):
    rules_path = _write(tmp_path / "rules.json", {
        "rules": [{"rule_id": "a", "name": "A", "version": "1.0.0", "conditions": [], "actions": []}]
    })

    code = main(["validate", "--rules", str(rules_path)])

    assert code == 0
    out = capsys.readouterr().out
    assert "OK" in out and "1 rule(s)" in out and "a" in out


def test_validate_invalid_rules_file_exits_one_and_names_the_problem(tmp_path, capsys):
    rules_path = _write(tmp_path / "rules.json", {"rules": "not-a-list"})

    code = main(["validate", "--rules", str(rules_path)])

    assert code == 1
    out = capsys.readouterr().out
    assert "FAIL" in out and "must be an array" in out


def test_validate_valid_device_config_exits_zero(tmp_path, capsys):
    config_path = _write(tmp_path / "device.json", {"device_id": "dev-1", "tenant_id": "t"})

    code = main(["validate", "--device-config", str(config_path)])

    assert code == 0
    out = capsys.readouterr().out
    assert "OK" in out and "dev-1" in out


def test_validate_both_files_one_bad_one_good_exits_one(tmp_path, capsys):
    rules_path = _write(tmp_path / "rules.json", {"rules": []})
    config_path = _write(tmp_path / "device.json", {"not_device_id": "oops"})

    code = main(["validate", "--rules", str(rules_path), "--device-config", str(config_path)])

    assert code == 1
    out = capsys.readouterr().out
    assert "OK" in out  # the rules file
    assert "FAIL" in out  # the device config


def test_validate_with_no_files_passed_exits_two():
    code = main(["validate"])
    assert code == 2


# ---- run ----

def test_run_dev_sensor_processes_real_events_end_to_end(tmp_path, capsys):
    log_path = tmp_path / "decisions.jsonl"

    code = main([
        "--log-path", str(log_path),
        "run", "--sensor", "dev", "--device-id", "test-dev",
        "--no-exporter", "--max-events", "5", "--dev-interval", "0",
    ])

    assert code == 0
    out = capsys.readouterr().out
    assert "processed 5 event(s)" in out

    log = EventLog(log_path)
    assert log.count() == 5
    rows = log.recent(5)
    assert all(row["decision"]["action"] == "allow" for row in rows)  # no rules loaded -> default allow


def test_run_applies_real_policy_rules_from_a_file(tmp_path, capsys):
    log_path = tmp_path / "decisions.jsonl"
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(json.dumps({
        "policy_version": "pilot-test",
        "rules": [{
            "rule_id": "deny-network", "name": "x", "version": "1.0.0",
            "conditions": [{"type": "flow", "match": {"dst_port": [443]}}],
            "actions": [{"type": "deny", "message": "blocked"}],
        }]
    }))

    code = main([
        "--log-path", str(log_path),
        "run", "--sensor", "dev", "--device-id", "test-dev",
        "--no-exporter", "--rules", str(rules_path), "--max-events", "20", "--dev-interval", "0",
    ])

    assert code == 0
    log = EventLog(log_path)
    rows = log.recent(20)
    network_rows = [r for r in rows if r["event_ref"]["class"] == "network_flow"]
    assert network_rows, "DevModeSensor should have produced at least one network_flow in 20 events"
    assert all(r["decision"]["action"] == "deny" for r in network_rows)
    assert all(r["rule"]["rule_id"] == "deny-network" for r in network_rows)
    assert all(r["policy"]["version"] == "pilot-test" for r in network_rows)
    assert all(r["policy"]["hash"].startswith("sha256:") for r in network_rows)


def test_run_requires_device_id_without_device_config(tmp_path, capsys):
    code = main([
        "--log-path", str(tmp_path / "decisions.jsonl"),
        "run", "--sensor", "dev", "--max-events", "1",
    ])

    assert code == 2
    assert "--device-id is required" in capsys.readouterr().err


def test_run_invalid_rules_file_exits_one_and_names_the_problem(tmp_path, capsys):
    rules_path = tmp_path / "rules.json"
    rules_path.write_text("{not valid json")

    code = main([
        "--log-path", str(tmp_path / "decisions.jsonl"),
        "run", "--sensor", "dev", "--device-id", "test-dev",
        "--no-exporter", "--rules", str(rules_path), "--max-events", "1",
    ])

    assert code == 1
    assert "not valid JSON" in capsys.readouterr().err


def test_run_process_exec_sensor_without_root_fails_cleanly(tmp_path, capsys):
    """Confirms the CLI surfaces LinuxEbpfSensor's PermissionError as a clean exit(1)
    message, not an uncaught traceback -- this test itself is not expected to run as root."""
    import os

    if os.geteuid() == 0:
        import pytest

        pytest.skip("running as root -- this test asserts the non-root failure path specifically")

    code = main([
        "--log-path", str(tmp_path / "decisions.jsonl"),
        "run", "--sensor", "process-exec", "--device-id", "test-dev", "--no-exporter",
    ])

    assert code == 1
    assert "requires root" in capsys.readouterr().err
