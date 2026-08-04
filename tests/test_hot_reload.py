"""
Tests for PolicyHotReloader (shield/config/hot_reload.py, spec §4.6).

Every test writes a real file, waits for a real mtime to actually change (filesystem mtime
resolution can be coarser than "instant" on some systems, so tests bump mtime explicitly via
os.utime rather than relying on wall-clock timing alone), and calls the real
`check_and_reload()` -- no mocked clock, no fake filesystem.
"""

from __future__ import annotations

import json
import os

from shield.config import PolicyHotReloader
from shield.policy_engine import PolicyEngine


def _write_rules(path, rule_ids: list[str]):
    path.write_text(json.dumps({
        "rules": [
            {"rule_id": rid, "name": rid, "version": "1.0.0", "conditions": [], "actions": [{"type": "allow"}]}
            for rid in rule_ids
        ]
    }))


def _bump_mtime(path, seconds_forward: float):
    st = path.stat()
    os.utime(path, (st.st_atime + seconds_forward, st.st_mtime + seconds_forward))


def test_first_check_loads_initial_rules(tmp_path):
    path = tmp_path / "rules.json"
    _write_rules(path, ["a"])

    engine = PolicyEngine(rules=[])
    reloader = PolicyHotReloader(engine, path)

    reloaded = reloader.check_and_reload()

    assert reloaded is True
    assert [r.rule_id for r in engine.rules] == ["a"]


def test_unchanged_file_does_not_reload(tmp_path):
    path = tmp_path / "rules.json"
    _write_rules(path, ["a"])

    engine = PolicyEngine(rules=[])
    reloader = PolicyHotReloader(engine, path)
    reloader.check_and_reload()

    reloaded_again = reloader.check_and_reload()

    assert reloaded_again is False
    assert [r.rule_id for r in engine.rules] == ["a"]  # untouched


def test_real_edit_is_picked_up(tmp_path):
    path = tmp_path / "rules.json"
    _write_rules(path, ["a"])

    engine = PolicyEngine(rules=[])
    reloader = PolicyHotReloader(engine, path)
    reloader.check_and_reload()

    _write_rules(path, ["a", "b", "c"])
    _bump_mtime(path, 5)

    reloaded = reloader.check_and_reload()

    assert reloaded is True
    assert [r.rule_id for r in engine.rules] == ["a", "b", "c"]


def test_malformed_edit_keeps_last_known_good_rules(tmp_path):
    """The core safety property: a bad edit must never zero out or crash a live engine."""
    path = tmp_path / "rules.json"
    _write_rules(path, ["a", "b"])

    engine = PolicyEngine(rules=[])
    reloader = PolicyHotReloader(engine, path)
    reloader.check_and_reload()
    assert [r.rule_id for r in engine.rules] == ["a", "b"]

    path.write_text("{not valid json")  # simulate a bad edit
    _bump_mtime(path, 5)

    reloaded = reloader.check_and_reload()

    assert reloaded is False
    assert [r.rule_id for r in engine.rules] == ["a", "b"]  # untouched, NOT zeroed out


def test_missing_file_keeps_last_known_good_rules(tmp_path):
    path = tmp_path / "rules.json"
    _write_rules(path, ["a"])

    engine = PolicyEngine(rules=[])
    reloader = PolicyHotReloader(engine, path)
    reloader.check_and_reload()

    path.unlink()

    reloaded = reloader.check_and_reload()

    assert reloaded is False
    assert [r.rule_id for r in engine.rules] == ["a"]


def test_recovers_after_a_malformed_edit_is_fixed(tmp_path):
    path = tmp_path / "rules.json"
    _write_rules(path, ["a"])

    engine = PolicyEngine(rules=[])
    reloader = PolicyHotReloader(engine, path)
    reloader.check_and_reload()

    path.write_text("{not valid json")
    _bump_mtime(path, 5)
    reloader.check_and_reload()
    assert [r.rule_id for r in engine.rules] == ["a"]  # still last-known-good

    _write_rules(path, ["a", "b"])
    _bump_mtime(path, 10)
    reloaded = reloader.check_and_reload()

    assert reloaded is True
    assert [r.rule_id for r in engine.rules] == ["a", "b"]
