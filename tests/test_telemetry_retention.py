from shield.backend.store import ShieldStore


def test_decision_telemetry_retention_is_bounded_and_keeps_fresh_rows(tmp_path):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    store.enroll_device(base_url="http://backend", tenant_id="tenant-a", device_id="device-a")
    old_id = store.record_decision(tenant_id="tenant-a", device_id="device-a", decision={"decision": {"action": "allow"}})
    fresh_id = store.record_decision(tenant_id="tenant-a", device_id="device-a", decision={"decision": {"action": "deny"}})
    with store._conn:
        store._conn.execute("UPDATE decisions SET received_at='2000-01-01T00:00:00Z' WHERE id=?", (old_id,))

    removed = store.prune_telemetry(max_age_days=1, limit=1)

    assert removed["decisions"] == 1
    assert store._conn.execute("SELECT COUNT(*) FROM decisions WHERE id=?", (old_id,)).fetchone()[0] == 0
    assert store._conn.execute("SELECT COUNT(*) FROM decisions WHERE id=?", (fresh_id,)).fetchone()[0] == 1
    store.close()


def test_unmatched_observations_roll_up_in_one_minute_bucket(tmp_path):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    store.enroll_device(base_url="http://backend", tenant_id="tenant-a", device_id="device-a")
    decision = {
        "event_ref": {"class": "process_activity"},
        "rule": {"rule_id": "_no_match"},
        "decision": {"action": "log_only", "severity": "low"},
    }

    first_id = store.record_decision(tenant_id="tenant-a", device_id="device-a", decision=decision)
    second_id = store.record_decision(tenant_id="tenant-a", device_id="device-a", decision=decision)

    assert first_id == second_id
    assert store._conn.execute("SELECT COUNT(*) FROM decisions").fetchone()[0] == 0
    row = store._conn.execute(
        "SELECT observation_count, sample_json FROM decision_observation_rollups"
    ).fetchone()
    assert row["observation_count"] == 2
    assert '"event_ref"' in row["sample_json"]
    summary = store.dashboard_summary(tenant_id="tenant-a")
    assert summary["decisions_by_action"] == {"log_only": 2}
    assert summary["decision_observation_rollups"][0]["count"] == 2
    store.close()


def test_observation_rollups_expire_with_one_day_telemetry_retention(tmp_path):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    store.enroll_device(base_url="http://backend", tenant_id="tenant-a", device_id="device-a")
    store.record_decision(
        tenant_id="tenant-a",
        device_id="device-a",
        decision={"rule": {"rule_id": "_no_match"}, "decision": {"action": "log_only"}},
    )
    with store._conn:
        store._conn.execute("UPDATE decision_observation_rollups SET bucket_start='2000-01-01T00:00:00Z'")

    removed = store.prune_telemetry(max_age_days=1, limit=1)

    assert removed["decision_observation_rollups"] == 1
    assert store._conn.execute("SELECT COUNT(*) FROM decision_observation_rollups").fetchone()[0] == 0
    store.close()
