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


def test_linux_posture_probe_is_explicit_not_inferred(monkeypatch):
    import shield.inventory as inventory
    monkeypatch.setattr(inventory.platform, "system", lambda: "Linux")
    monkeypatch.setattr(inventory.os.path, "exists", lambda path: False)
    monkeypatch.setattr(inventory.subprocess, "run", lambda *args, **kwargs: type("R", (), {"returncode": 1, "stdout": ""})())
    posture = inventory._posture()
    assert posture == {"secure_boot": "unknown", "disk_encryption": "unknown", "tpm": "disabled"}
