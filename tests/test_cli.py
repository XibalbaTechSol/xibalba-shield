"""
Tests for `shield validate` (shield/cli.py) -- exercises the real argparse wiring and the
real shield.config loader together, not just the loader in isolation (test_config.py already
covers that). Real temp files, real `main()` invocation, real captured stdout/exit code.
"""

from __future__ import annotations

import json

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
