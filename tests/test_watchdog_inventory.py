from shield.watchdog import Watchdog

def test_watchdog_retains_inventory_baseline_and_reports_drift(monkeypatch):
    snapshots = iter([{"snapshot_hash": "a" * 64}, {"snapshot_hash": "b" * 64}])
    monkeypatch.setattr("shield.inventory.collect_inventory", lambda: next(snapshots))
    watchdog = object.__new__(Watchdog)
    watchdog._previous_inventory = None
    first = watchdog._inventory_status()
    second = watchdog._inventory_status()
    assert first["drift"]["comparable"] is False
    assert second["drift"]["changed"] is True
    assert second["drift"]["previous_hash"] == "a" * 64
