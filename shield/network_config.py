"""Validated, secret-free configuration primitives for the network control plane."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


class NetworkConfigError(ValueError):
    pass


KNOWN_NETWORK_ACTIONS = frozenset({
    "block_flow",
    "block_domain",
    "isolate_device",
    "move_segment",
    "revoke_access",
    "rate_limit",
    "restore_access",
})


@dataclass(frozen=True)
class NetworkZone:
    zone_id: str
    kind: str
    protected: bool = False


@dataclass(frozen=True)
class NetworkTopology:
    network_id: str
    cidr: str
    segments: tuple[str, ...] = ()


@dataclass(frozen=True)
class NetworkSensor:
    sensor_id: str
    kind: str
    observation_point: str
    enabled: bool = True


@dataclass(frozen=True)
class NetworkConfig:
    zones: tuple[NetworkZone, ...]
    topology: tuple[NetworkTopology, ...]
    sensors: tuple[NetworkSensor, ...]
    protected_paths: frozenset[str]
    max_affected_devices: int
    max_affected_segments: int
    retention_days: int
    queue_limit_bytes: int
    adapter_actions: Mapping[str, frozenset[str]]

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "NetworkConfig":
        forbidden = {"password", "token", "secret", "private_key", "credential", "ssh_key"}
        def contains_forbidden(value: Any) -> bool:
            if isinstance(value, Mapping):
                return any(str(key).lower() in forbidden or contains_forbidden(item) for key, item in value.items())
            if isinstance(value, (list, tuple)):
                return any(contains_forbidden(item) for item in value)
            return False
        if contains_forbidden(raw):
            raise NetworkConfigError("network configuration must not contain credentials")
        zones = []
        seen: set[str] = set()
        allowed_kinds = {"management", "users", "servers", "regulated", "development", "guest", "iot", "quarantine", "egress", "recovery"}
        for item in raw.get("zones", []):
            zone_id = str(item.get("zone_id") or "")
            kind = str(item.get("kind") or "")
            if not zone_id or zone_id in seen or kind not in allowed_kinds:
                raise NetworkConfigError("zones require unique ids and supported kinds")
            seen.add(zone_id)
            zones.append(NetworkZone(zone_id, kind, bool(item.get("protected", False))))
        topology = []
        topology_seen: set[str] = set()
        for item in raw.get("topology", []):
            network_id = str(item.get("network_id") or "").strip()
            cidr = str(item.get("cidr") or "").strip()
            segments = tuple(str(segment).strip() for segment in item.get("segments", []))
            if not network_id or network_id in topology_seen or not cidr or any(not segment for segment in segments):
                raise NetworkConfigError("topology requires unique network ids and non-empty cidr/segments")
            topology_seen.add(network_id)
            topology.append(NetworkTopology(network_id, cidr, segments))
        sensors = []
        sensor_seen: set[str] = set()
        sensor_kinds = {"endpoint", "gateway", "dns", "firewall", "nac", "flow-exporter", "switch", "wifi"}
        observation_points = {"endpoint", "gateway", "dns", "firewall", "nac", "flow-exporter"}
        for item in raw.get("sensors", []):
            sensor_id = str(item.get("sensor_id") or "").strip()
            kind = str(item.get("kind") or "").strip()
            observation_point = str(item.get("observation_point") or "").strip()
            if not sensor_id or sensor_id in sensor_seen or kind not in sensor_kinds or observation_point not in observation_points:
                raise NetworkConfigError("sensors require unique ids and supported kinds/observation points")
            sensor_seen.add(sensor_id)
            sensors.append(NetworkSensor(sensor_id, kind, observation_point, bool(item.get("enabled", True))))
        if len(topology) > 100 or len(sensors) > 100:
            raise NetworkConfigError("topology and sensors are limited to 100 entries")
        protected = frozenset(str(value) for value in raw.get("protected_paths", []))
        required_kinds = {"management", "recovery"}
        if not required_kinds.issubset({zone.kind for zone in zones if zone.protected}):
            raise NetworkConfigError("management and recovery zones must be protected")
        max_devices = int(raw.get("max_affected_devices", 1))
        max_segments = int(raw.get("max_affected_segments", 1))
        retention = int(raw.get("retention_days", 7))
        queue_limit = int(raw.get("queue_limit_bytes", 16 * 1024 * 1024))
        if not (1 <= max_devices <= 1000 and 1 <= max_segments <= 100 and 1 <= retention <= 3650):
            raise NetworkConfigError("network limits are outside safe bounds")
        if not (64 * 1024 <= queue_limit <= 1024 * 1024 * 1024):
            raise NetworkConfigError("queue_limit_bytes is outside safe bounds")
        adapter_actions = {}
        for ref, actions in dict(raw.get("adapter_actions", {})).items():
            adapter_ref = str(ref).strip()
            action_set = frozenset(str(action).strip() for action in actions)
            if not adapter_ref or not action_set or not action_set.issubset(KNOWN_NETWORK_ACTIONS):
                raise NetworkConfigError("adapter_actions contain an unsupported or empty action")
            adapter_actions[adapter_ref] = action_set
        return cls(tuple(zones), tuple(topology), tuple(sensors), protected, max_devices, max_segments, retention, queue_limit, adapter_actions)


__all__ = ["KNOWN_NETWORK_ACTIONS", "NetworkConfig", "NetworkConfigError", "NetworkSensor", "NetworkTopology", "NetworkZone"]
