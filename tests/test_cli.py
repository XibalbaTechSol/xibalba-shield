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
from shield.config import load_policy_bundle
from shield.cli import main

import pytest
from unittest.mock import AsyncMock, patch
from integrity_sdk.policy.opa_client import OPADecision

@pytest.fixture(autouse=True)
def mock_opa():
    with patch("shield.policy_engine.engine.opa_evaluate", new_callable=AsyncMock) as mock_eval:
        mock_eval.return_value = OPADecision(allow=True, raw_result={"action": "allow"})
        yield mock_eval


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
        "--max-events", "5", "--dev-interval", "0",
    ])

    assert code == 0
    out = capsys.readouterr().out
    assert "processed 5 event(s)" in out

    log = EventLog(log_path)
    assert log.count() == 5
    rows = log.recent(5)
    assert all(row["decision"]["action"] == "allow" for row in rows)  # no rules loaded -> default allow


def test_events_prints_export_status(tmp_path, capsys):
    log_path = tmp_path / "decisions.jsonl"
    code = main([
        "--log-path", str(log_path),
        "run", "--sensor", "dev", "--device-id", "test-dev",
        "--max-events", "1", "--dev-interval", "0",
    ])
    assert code == 0
    capsys.readouterr()

    code = main(["--log-path", str(log_path), "events", "--recent", "1"])

    assert code == 0
    assert "export=ok" in capsys.readouterr().out


def test_verify_log_command_detects_tamper_evident_log(tmp_path, capsys):
    log_path = tmp_path / "decisions.jsonl"
    key_path = tmp_path / "log.key"
    key_path.write_bytes(b"test-secret")

    code = main([
        "--log-path", str(log_path),
        "run", "--sensor", "dev", "--device-id", "test-dev",
        "--max-events", "1", "--dev-interval", "0",
        "--log-integrity-key", str(key_path),
    ])
    assert code == 0
    capsys.readouterr()

    code = main(["--log-path", str(log_path), "verify-log", "--integrity-key", str(key_path)])

    assert code == 0
    assert "verified 1 decision log entries" in capsys.readouterr().out


def test_siem_export_command_requires_one_destination(tmp_path, capsys):
    code = main(["--log-path", str(tmp_path / "decisions.jsonl"), "siem-export"])

    assert code == 2
    assert "exactly one" in capsys.readouterr().err


def test_siem_export_command_writes_jsonl(tmp_path, capsys):
    log_path = tmp_path / "decisions.jsonl"
    output_path = tmp_path / "siem.jsonl"

    code = main([
        "--log-path", str(log_path),
        "run", "--sensor", "dev", "--device-id", "test-dev",
        "--max-events", "1", "--dev-interval", "0",
    ])
    assert code == 0
    capsys.readouterr()

    code = main(["--log-path", str(log_path), "siem-export", "--output", str(output_path)])

    assert code == 0
    assert "exported=1" in capsys.readouterr().out
    assert json.loads(output_path.read_text())["event.module"] == "xibalba-shield"


def test_run_applies_real_policy_rules_from_a_file(tmp_path, capsys, mock_opa):
    mock_opa.return_value = OPADecision(allow=False, raw_result={"action": "deny", "rule_id": "deny-network"})
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
        "--rules", str(rules_path), "--max-events", "20", "--dev-interval", "0",
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
        "--rules", str(rules_path), "--max-events", "1",
    ])

    assert code == 1
    assert "not valid JSON" in capsys.readouterr().err


def test_run_rejects_policy_hash_not_trusted_by_device_config(tmp_path, capsys):
    rules_path = _write(tmp_path / "rules.json", {
        "rules": [{"rule_id": "a", "conditions": [{"type": "process", "match": {"name": ["bash"]}}],
                   "actions": [{"type": "allow"}]}],
    })
    config_path = _write(tmp_path / "device.json", {
        "device_id": "test-dev",
        "trusted_policy_hashes": ["sha256:not-this-file"],
    })

    code = main([
        "--log-path", str(tmp_path / "decisions.jsonl"),
        "run", "--sensor", "dev", "--device-config", str(config_path),
        "--rules", str(rules_path), "--max-events", "1", "--dev-interval", "0",
    ])

    assert code == 1
    assert "not trusted" in capsys.readouterr().err


def test_run_accepts_policy_hash_trusted_by_device_config(tmp_path, capsys):
    rules_path = _write(tmp_path / "rules.json", {
        "rules": [{"rule_id": "a", "conditions": [{"type": "process", "match": {"name": ["bash"]}}],
                   "actions": [{"type": "allow"}]}],
    })
    policy_hash = load_policy_bundle(rules_path).hash
    config_path = _write(tmp_path / "device.json", {
        "device_id": "test-dev",
        "trusted_policy_hashes": [policy_hash],
    })

    code = main([
        "--log-path", str(tmp_path / "decisions.jsonl"),
        "run", "--sensor", "dev", "--device-config", str(config_path),
        "--rules", str(rules_path), "--max-events", "1", "--dev-interval", "0",
    ])

    assert code == 0


def test_run_process_exec_sensor_without_root_fails_cleanly(tmp_path, capsys):
    """Confirms the CLI surfaces LinuxEbpfSensor's PermissionError as a clean exit(1)
    message, not an uncaught traceback -- this test itself is not expected to run as root."""
    import os

    if os.geteuid() == 0:
        import pytest

        pytest.skip("running as root -- this test asserts the non-root failure path specifically")

    code = main([
        "--log-path", str(tmp_path / "decisions.jsonl"),
        "run", "--sensor", "process-exec", "--device-id", "test-dev",
    ])

    assert code == 1
    assert "requires root" in capsys.readouterr().err


def test_run_tcp_connect_sensor_without_root_fails_cleanly(tmp_path, capsys):
    import os

    if os.geteuid() == 0:
        import pytest

        pytest.skip("running as root -- this test asserts the non-root failure path specifically")

    code = main([
        "--log-path", str(tmp_path / "decisions.jsonl"),
        "run", "--sensor", "tcp-connect", "--device-id", "test-dev",
    ])

    assert code == 1
    assert "requires root" in capsys.readouterr().err
