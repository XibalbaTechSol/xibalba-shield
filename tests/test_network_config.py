import pytest

from shield.network_config import NetworkConfig, NetworkConfigError


def _config(**changes):
    value = {
        "zones": [
            {"zone_id": "mgmt", "kind": "management", "protected": True},
            {"zone_id": "recovery", "kind": "recovery", "protected": True},
            {"zone_id": "users", "kind": "users"},
        ],
        "protected_paths": ["sha256:" + "1" * 64],
        "adapter_actions": {"dns-a": ["block_domain"]},
    }
    value.update(changes)
    return value


def test_network_config_requires_protected_recovery_boundaries():
    config = NetworkConfig.from_mapping(_config())
    assert {zone.kind for zone in config.zones if zone.protected} == {"management", "recovery"}
    assert config.adapter_actions["dns-a"] == frozenset({"block_domain"})


def test_network_config_rejects_secrets_and_unbounded_limits():
    with pytest.raises(NetworkConfigError, match="credentials"):
        NetworkConfig.from_mapping(_config(token="secret"))
    with pytest.raises(NetworkConfigError, match="limits"):
        NetworkConfig.from_mapping(_config(max_affected_devices=0))


def test_network_config_rejects_missing_protected_zone_or_duplicate_ids():
    with pytest.raises(NetworkConfigError, match="management and recovery"):
        NetworkConfig.from_mapping(_config(zones=[{"zone_id": "users", "kind": "users"}]))
    with pytest.raises(NetworkConfigError, match="unique"):
        NetworkConfig.from_mapping(_config(zones=[{"zone_id": "mgmt", "kind": "management", "protected": True}, {"zone_id": "mgmt", "kind": "recovery", "protected": True}]))


def test_network_config_rejects_untyped_adapter_actions():
    with pytest.raises(NetworkConfigError, match="unsupported"):
        NetworkConfig.from_mapping(_config(adapter_actions={"dns-a": ["execute_shell"]}))


def test_network_config_validates_topology_and_sensors_and_never_accepts_nested_credentials():
    config = NetworkConfig.from_mapping(_config(
        topology=[{"network_id": "corp", "cidr": "192.0.2.0/24", "segments": ["users"]}],
        sensors=[{"sensor_id": "dns-a", "kind": "dns", "observation_point": "dns", "enabled": True}],
    ))
    assert config.topology[0].network_id == "corp"
    assert config.sensors[0].observation_point == "dns"
    with pytest.raises(NetworkConfigError, match="credentials"):
        NetworkConfig.from_mapping(_config(sensors=[{"sensor_id": "dns-a", "kind": "dns", "observation_point": "dns", "token": "secret"}]))
