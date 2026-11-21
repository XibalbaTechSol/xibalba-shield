from shield.inventory import collect_inventory, inventory_drift

def test_inventory_has_stable_canonical_hash():
    inv = collect_inventory(max_processes=1, max_packages=1)
    assert len(inv["snapshot_hash"]) == 64
    assert inventory_drift(inv, dict(inv))["changed"] is False

def test_inventory_drift_reports_hash_change_without_values():
    old = {"snapshot_hash": "a" * 64}
    new = {"snapshot_hash": "b" * 64, "secret": "must not be returned"}
    result = inventory_drift(old, new)
    assert result["changed"] is True
    assert "secret" not in result

def test_inventory_drift_is_unknown_without_baseline():
    assert inventory_drift(None, {"snapshot_hash": "a" * 64})["comparable"] is False
