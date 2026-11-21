from shield.watchdog import Watchdog

def test_watchdog_retains_inventory_baseline_and_reports_drift(monkeypatch):
    snapshots = iter([{"snapshot_hash": "a" * 64}, {"snapshot_hash": "b" * 64}])
    monkeypatch.setattr("shield.inventory.collect_inventory", lambda: next(snapshots))
    watchdog = object.__new__(Watchdog)
    watchdog._inventory_state_file = None
    watchdog._previous_inventory = None
    first = watchdog._inventory_status()
    second = watchdog._inventory_status()
    assert first["drift"]["comparable"] is False
    assert second["drift"]["changed"] is True
    assert second["drift"]["previous_hash"] == "a" * 64


def test_watchdog_persists_hash_for_restart(monkeypatch, tmp_path):
    monkeypatch.setattr("shield.inventory.collect_inventory", lambda: {"snapshot_hash": "c" * 64})
    state = tmp_path / "inventory-state.json"
    first = object.__new__(Watchdog)
    first._inventory_state_file = state
    first._previous_inventory = first._load_inventory_baseline()
    first._inventory_status()
    second = object.__new__(Watchdog)
    second._inventory_state_file = state
    second._previous_inventory = second._load_inventory_baseline()
    assert second._previous_inventory == {"snapshot_hash": "c" * 64}
