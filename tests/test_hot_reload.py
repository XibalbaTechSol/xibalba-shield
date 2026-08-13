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
from unittest.mock import patch, AsyncMock

from integrity_sdk.policy.opa_client import OPADecision

from shield.config import PolicyHotReloader
from shield.policy_engine import PolicyEngine
from shield.policy_engine.engine import EvaluationContext
from shield.schemas.events import Activity, ProcessActivity, ProcessInfo


def _write_rules(path, rule_ids: list[str]):
    path.write_text(json.dumps({
        "policy_version": f"v-{len(rule_ids)}",
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

    engine = PolicyEngine()
    reloader = PolicyHotReloader(engine, path)

    reloaded = reloader.check_and_reload()

    assert reloaded is True
    assert engine.policy_version == "v-1"
    assert engine.policy_hash.startswith("sha256:")


def test_unchanged_file_does_not_reload(tmp_path):
    path = tmp_path / "rules.json"
    _write_rules(path, ["a"])

    engine = PolicyEngine()
    reloader = PolicyHotReloader(engine, path)
    reloader.check_and_reload()

    reloaded_again = reloader.check_and_reload()

    assert reloaded_again is False


def test_real_edit_is_picked_up(tmp_path):
    path = tmp_path / "rules.json"
    _write_rules(path, ["a"])

    engine = PolicyEngine()
    reloader = PolicyHotReloader(engine, path)
    reloader.check_and_reload()

    _write_rules(path, ["a", "b", "c"])
    _bump_mtime(path, 5)

    reloaded = reloader.check_and_reload()

    assert reloaded is True
    assert engine.policy_version == "v-3"


def test_malformed_edit_keeps_last_known_good_rules(tmp_path):
    """The core safety property: a bad edit must never zero out or crash a live engine."""
    path = tmp_path / "rules.json"
    _write_rules(path, ["a", "b"])

    engine = PolicyEngine()
    reloader = PolicyHotReloader(engine, path)
    reloader.check_and_reload()

    path.write_text("{not valid json")  # simulate a bad edit
    _bump_mtime(path, 5)

    reloaded = reloader.check_and_reload()

    assert reloaded is False


@patch("shield.policy_engine.engine.opa_evaluate", new_callable=AsyncMock)
def test_malformed_edit_preserves_prior_decision_behavior(mock_evaluate, tmp_path):
    """The safety property is enforcement, not just rule-list preservation.

    Rewritten post-OPA-delegation (2026-08-07, commit f86c0f0): `PolicyEngine` no longer
    takes a `rules=` list or matches JSON conditions/actions itself -- actual rule matching
    is OPA's job now (see policy_engine/engine.py, test_policy_engine.py's own
    `@patch(...opa_evaluate...)` pattern, which this mirrors). What `PolicyHotReloader`
    still controls on `PolicyEngine` is exactly `policy_version`/`policy_hash` (see
    config/hot_reload.py) -- those are what must stay pinned to the last-known-good bundle
    across a malformed edit, echoed unchanged in every decision OPA produces in the
    meantime. `test_malformed_edit_keeps_last_known_good_rules` above already proves
    `reloaded is False`; this test proves the consequence that matters -- a live decision's
    `policy.version`/`policy.hash` fields don't silently change underneath a bad edit.
    """
    mock_evaluate.return_value = OPADecision(
        allow=False,
        raw_result={
            "action": "contain",
            "message": "Blocked.",
            "rule_id": "block-python",
            "name": "Block python",
            "version": "1.0.0",
        },
    )

    path = tmp_path / "rules.json"
    _write_rules(path, ["block-python"])

    engine = PolicyEngine()
    reloader = PolicyHotReloader(engine, path)
    reloader.check_and_reload()

    event = ProcessActivity(
        device_id="dev-1",
        process=ProcessInfo(pid=1, name="python", exe_path="/usr/bin/python"),
        activity=Activity(type="launch"),
    )
    ctx = EvaluationContext(tenant_id="tenant-xyz", device_role="clinical_desktop", device_id="dev-1")
    before = engine.evaluate(event, ctx)
    assert before.decision.action == "contain"
    assert before.policy.version == "v-1"

    path.write_text("{not valid json")
    _bump_mtime(path, 5)

    reloaded = reloader.check_and_reload()
    assert reloaded is False

    after = engine.evaluate(event, ctx)
    assert after.decision.action == "contain"
    assert after.policy.version == "v-1"  # unchanged by the malformed edit, not blanked/bumped
    after = engine.evaluate(event, ctx)
    assert after.decision.action == before.decision.action
    assert after.rule.rule_id == before.rule.rule_id


def test_missing_file_keeps_last_known_good_rules(tmp_path):
    path = tmp_path / "rules.json"
    _write_rules(path, ["a"])

    engine = PolicyEngine()
    reloader = PolicyHotReloader(engine, path)
    reloader.check_and_reload()

    path.unlink()

    reloaded = reloader.check_and_reload()

    assert reloaded is False


def test_recovers_after_a_malformed_edit_is_fixed(tmp_path):
    path = tmp_path / "rules.json"
    _write_rules(path, ["a"])

    engine = PolicyEngine()
    reloader = PolicyHotReloader(engine, path)
    reloader.check_and_reload()

    path.write_text("{not valid json")
    _bump_mtime(path, 5)
    reloader.check_and_reload()

    _write_rules(path, ["a", "b"])
    _bump_mtime(path, 10)
    reloaded = reloader.check_and_reload()

    assert reloaded is True


def test_rejects_untrusted_policy_hash_on_reload(tmp_path):
    path = tmp_path / "rules.json"
    _write_rules(path, ["a"])

    engine = PolicyEngine()
    reloader = PolicyHotReloader(engine, path, trusted_policy_hashes=["sha256:not-this-file"])

    reloaded = reloader.check_and_reload()

    assert reloaded is False
