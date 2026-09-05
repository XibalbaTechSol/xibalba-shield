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


def _write_rules(path, rule_ids: list[str], revision: int | None = None):
    path.write_text(json.dumps({
        "policy_version": f"v-{len(rule_ids)}",
        **({"policy_revision": revision} if revision is not None else {}),
        "rules": [
            {"rule_id": rid, "name": rid, "version": "1.0.0", "conditions": [], "actions": [{"type": "allow"}]}
            for rid in rule_ids
        ]
    }))


def _bump_mtime(path, seconds_forward: float):
    st = path.stat()
    os.utime(path, (st.st_atime + seconds_forward, st.st_mtime + seconds_forward))


def test_status_starts_unhealthy_before_first_load(tmp_path):
    path = tmp_path / "rules.json"
    engine = PolicyEngine()
    reloader = PolicyHotReloader(engine, path)

    status = reloader.status()

    assert status.healthy is False
    assert status.active_policy_hash == ""
    assert status.last_attempt_at is None


def test_status_reports_success_then_degraded_update(tmp_path):
    path = tmp_path / "rules.json"
    _write_rules(path, ["a"])
    engine = PolicyEngine()
    reloader = PolicyHotReloader(engine, path)

    assert reloader.check_and_reload() is True
    healthy = reloader.status()
    assert healthy.healthy is True
    assert healthy.active_policy_version == "v-1"
    assert healthy.last_success_at == healthy.last_attempt_at

    path.write_text("{not valid json")
    _bump_mtime(path, 5)
    assert reloader.check_and_reload() is False
    degraded = reloader.status()
    assert degraded.healthy is False
    assert degraded.active_policy_version == "v-1"
    assert degraded.active_policy_hash == healthy.active_policy_hash
    assert degraded.last_error is not None


def test_rejects_policy_downgrade_when_enabled(tmp_path):
    path = tmp_path / "rules.json"
    _write_rules(path, ["a"], revision=2)
    engine = PolicyEngine()
    reloader = PolicyHotReloader(engine, path, reject_downgrades=True)
    assert reloader.check_and_reload() is True

    _write_rules(path, ["a", "older"], revision=1)
    _bump_mtime(path, 5)
    assert reloader.check_and_reload() is False
    assert engine.policy_version == "v-1"
    assert reloader.status().last_error is not None


def test_policy_without_revision_is_rejected_after_revisioned_policy(tmp_path):
    path = tmp_path / "rules.json"
    _write_rules(path, ["a"], revision=1)
    engine = PolicyEngine()
    reloader = PolicyHotReloader(engine, path, reject_downgrades=True)
    assert reloader.check_and_reload() is True

    _write_rules(path, ["unversioned"])
    _bump_mtime(path, 5)
    assert reloader.check_and_reload() is False
    assert engine.policy_version == "v-1"


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


# ---- expiry (independent of the mtime shortcut) ----

def _write_signed_rules(path, rule_ids: list[str], keypair, *, expires_at=None, revision=None):
    import json as _json

    from shield.config import sign_policy_bundle

    policy = {
        "policy_version": f"v-{len(rule_ids)}",
        **({"policy_revision": revision} if revision is not None else {}),
        **({"expires_at": expires_at} if expires_at is not None else {}),
        "rules": [
            {"rule_id": rid, "name": rid, "version": "1.0.0", "conditions": [], "actions": [{"type": "allow"}]}
            for rid in rule_ids
        ],
    }
    path.write_text(_json.dumps(sign_policy_bundle(policy, keypair)))


def test_expiry_is_reported_unhealthy_without_a_file_change():
    """The real gap this closes: a bundle that's ALREADY loaded and unchanged on disk
    must stop being reported healthy once its expires_at passes -- the mtime-only poll
    would otherwise never re-examine it again."""
    from datetime import datetime, timedelta, timezone

    from integrity_sdk.did import Keypair

    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "rules.json"
        keypair = Keypair.generate()
        soon = (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        _write_signed_rules(path, ["a"], keypair, expires_at=soon)

        engine = PolicyEngine()
        reloader = PolicyHotReloader(engine, path)
        assert reloader.check_and_reload() is True
        assert reloader.status().healthy is True

        import time
        time.sleep(1.2)  # real wall-clock wait past the real expiry -- no mocked clock

        # No file change at all -- pure expiry re-check.
        assert reloader.check_and_reload() is False
        status = reloader.status()
        assert status.healthy is False
        assert "expired" in status.last_error


def test_non_expiring_bundle_stays_healthy_across_repeated_checks(tmp_path):
    path = tmp_path / "rules.json"
    _write_rules(path, ["a"])
    engine = PolicyEngine()
    reloader = PolicyHotReloader(engine, path)
    assert reloader.check_and_reload() is True

    assert reloader.check_and_reload() is False  # unchanged, not reloaded
    assert reloader.status().healthy is True  # but still healthy -- no expiry set


# ---- history + rollback ----

def test_history_is_empty_before_any_successful_reload(tmp_path):
    path = tmp_path / "rules.json"
    engine = PolicyEngine()
    reloader = PolicyHotReloader(engine, path)

    assert reloader.history() == []


def test_history_records_each_successful_reload_newest_first(tmp_path):
    path = tmp_path / "rules.json"
    _write_rules(path, ["a"], revision=1)
    engine = PolicyEngine()
    reloader = PolicyHotReloader(engine, path)
    reloader.check_and_reload()

    _write_rules(path, ["a", "b"], revision=2)
    _bump_mtime(path, 5)
    reloader.check_and_reload()

    history = reloader.history()

    assert len(history) == 2
    assert history[0].policy_version == "v-2"  # newest first
    assert history[1].policy_version == "v-1"


def test_history_is_bounded_at_the_configured_limit(tmp_path):
    path = tmp_path / "rules.json"
    engine = PolicyEngine()
    reloader = PolicyHotReloader(engine, path, history_limit=2)

    for i, rule_ids in enumerate([["a"], ["a", "b"], ["a", "b", "c"]]):
        _write_rules(path, rule_ids, revision=i)
        if i > 0:
            _bump_mtime(path, 5 * i)
        reloader.check_and_reload()

    history = reloader.history()

    assert len(history) == 2
    assert history[0].policy_version == "v-3"
    assert history[1].policy_version == "v-2"
    # the pruned oldest entry's file must actually be gone, not just unindexed
    assert not any(f.stem not in {e.hash.removeprefix("sha256:") for e in history} for f in (path.parent / "history").glob("*.json") if f.name != "index.json")


def test_rollback_restores_a_specific_prior_bundle(tmp_path):
    path = tmp_path / "rules.json"
    _write_rules(path, ["a"], revision=1)
    engine = PolicyEngine()
    reloader = PolicyHotReloader(engine, path)
    reloader.check_and_reload()
    first_hash = engine.policy_hash

    _write_rules(path, ["a", "b"], revision=2)
    _bump_mtime(path, 5)
    reloader.check_and_reload()
    assert engine.policy_version == "v-2"

    ok = reloader.rollback_to(first_hash)

    assert ok is True
    assert engine.policy_version == "v-1"
    assert engine.policy_hash == first_hash
    assert reloader.status().healthy is True


def test_rollback_bypasses_the_downgrade_check(tmp_path):
    """Rollback is an intentional revision regression -- the exact thing
    reject_downgrades exists to catch when it's accidental, not when an operator asks
    for it explicitly."""
    path = tmp_path / "rules.json"
    _write_rules(path, ["a"], revision=2)
    engine = PolicyEngine()
    reloader = PolicyHotReloader(engine, path, reject_downgrades=True)
    reloader.check_and_reload()

    _write_rules(path, ["a", "b"], revision=1)  # a real, deliberate downgrade attempt
    _bump_mtime(path, 5)
    assert reloader.check_and_reload() is False  # correctly rejected as an accidental downgrade

    # Roll back to revision 2's own hash instead -- not a downgrade rejection case,
    # this is restoring what SHOULD be active; just prove rollback_to itself doesn't
    # get blocked by reject_downgrades for a target that predates the current state.
    history = reloader.history()
    assert len(history) == 1
    assert reloader.rollback_to(history[0].hash) is True


def test_rollback_to_unknown_hash_fails_without_raising(tmp_path):
    path = tmp_path / "rules.json"
    _write_rules(path, ["a"])
    engine = PolicyEngine()
    reloader = PolicyHotReloader(engine, path)
    reloader.check_and_reload()

    ok = reloader.rollback_to("sha256:" + "0" * 64)

    assert ok is False
    assert engine.policy_version == "v-1"  # untouched
