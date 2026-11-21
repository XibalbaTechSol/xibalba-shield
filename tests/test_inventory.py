from shield.inventory import collect_inventory

def test_inventory_is_bounded_and_metadata_only():
    inv = collect_inventory(max_processes=2, max_packages=3)
    assert inv["schema"] == "xibalba.shield.inventory.v1"
    assert len(inv["processes"]) <= 2
    assert len(inv["packages"]) <= 3
    assert all(set(p) <= {"pid", "name", "username", "status"} for p in inv["processes"])
    assert "cmdline" not in str(inv)

def test_inventory_rejects_unbounded_limits():
    import pytest
    with pytest.raises(ValueError): collect_inventory(max_processes=0)
