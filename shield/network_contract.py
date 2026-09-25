"""Bounded, redacted network telemetry for the Shield/Hermes boundary."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker

SCHEMA = "xibalba.shield.hermes.network_event"
VERSION = "1.0.0"
SCHEMA_PATH = Path(__file__).with_name("schemas") / "xibalba.shield.hermes.network_event.schema.json"
_VALIDATOR = Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")), format_checker=FormatChecker())
_SECRET = re.compile(r"(?i)(bearer\s+\S+|password\s*[:=]\s*\S+|private[_ -]?key\s*[:=]\s*\S+|cookie\s*[:=]\s*\S+|authorization\s*[:=]\s*\S+)")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_RAW_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class NetworkContractError(ValueError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def opaque_ref(value: Any, *, key: bytes | None = None) -> str:
    data = str(value).encode("utf-8")
    digest = hmac.new(key, data, hashlib.sha256).hexdigest() if key else hashlib.sha256(data).hexdigest()
    return "sha256:" + digest


def _policy_hash(policy: Mapping[str, Any]) -> str:
    value = str(policy.get("policy_hash") or "")
    return value if re.fullmatch(r"sha256:[0-9a-f]{64}", value) else "sha256:" + "0" * 64


def _bounded_int(value: Any, maximum: int) -> int:
    try:
        return max(0, min(maximum, int(value or 0)))
    except (TypeError, ValueError):
        return 0


def build_network_event(
    observed: Mapping[str, Any],
    *,
    network_id: str,
    segment_id: str,
    observation_point: str,
    sensor_id: str,
    device_id: str,
    identity_source: str = "unknown",
    posture: str = "unknown",
    sequence: int = 0,
    ref_key: bytes | None = None,
    policy: Mapping[str, Any] | None = None,
    enforcement: Mapping[str, Any] | None = None,
    loss_count: int = 0,
    acknowledged: bool = False,
) -> dict[str, Any]:
    """Normalize one local network observation; raw identifiers never enter the result."""
    kind = str(observed.get("class") or observed.get("event_class") or "flow")
    flow_in = observed.get("flow") if isinstance(observed.get("flow"), Mapping) else {}
    dns_in = observed.get("dns") if isinstance(observed.get("dns"), Mapping) else {}
    policy = dict(policy or {})
    enforcement = dict(enforcement or {})
    event_id = str(observed.get("event_id") or opaque_ref(f"{network_id}:{segment_id}:{sequence}:{kind}", key=ref_key))
    action = str(observed.get("action") or "observed")[:64]
    event: dict[str, Any] = {
        "class": kind,
        "action": action,
        "severity": str(observed.get("severity") or "low"),
        "confidence": max(0.0, min(1.0, float(observed.get("confidence", 0.0) or 0.0))),
        "observed_fact": bool(observed.get("observed_fact", True)),
        "inference": bool(observed.get("inference", False)),
    }
    if kind == "flow":
        event["flow"] = {
            "direction": str(flow_in.get("direction") or "egress"),
            "protocol": str(flow_in.get("protocol") or "other"),
            "service_class": str(flow_in.get("service_class") or "unknown"),
            "destination_class": str(flow_in.get("destination_class") or "unknown"),
            "destination_ref": opaque_ref(flow_in.get("destination") or flow_in.get("dst_ip") or "unknown", key=ref_key),
            "destination_port": _bounded_int(flow_in.get("destination_port") or flow_in.get("dst_port"), 65535),
            "bytes_out": _bounded_int(flow_in.get("bytes_out"), 9223372036854775807),
            "bytes_in": _bounded_int(flow_in.get("bytes_in"), 9223372036854775807),
            "connection_count": _bounded_int(flow_in.get("connection_count"), 1000000),
            "duration_ms": _bounded_int(flow_in.get("duration_ms"), 86400000),
        }
    elif kind == "dns":
        event["dns"] = {
            "query_class": str(dns_in.get("query_class") or "unknown"),
            "domain_ref": opaque_ref(dns_in.get("domain") or dns_in.get("query_name") or "unknown", key=ref_key),
            "answer_class": str(dns_in.get("answer_class") or "unknown"),
        }
    elif kind in {"sensor_health", "configuration_change"}:
        event["health" if kind == "sensor_health" else "change"] = dict(observed.get("health" if kind == "sensor_health" else "change") or {})
    payload: dict[str, Any] = {
        "schema": SCHEMA, "schema_version": VERSION, "event_id": event_id,
        "sequence": _bounded_int(sequence, 9223372036854775807), "observed_at": str(observed.get("observed_at") or _now()),
        "network": {"network_id": opaque_ref(network_id, key=ref_key), "segment_id": opaque_ref(segment_id, key=ref_key), "observation_point": observation_point, "sensor_id": opaque_ref(sensor_id, key=ref_key)},
        "device": {"device_id": opaque_ref(device_id, key=ref_key), "identity_source": identity_source, "posture": posture, "confidence": max(0.0, min(1.0, float(observed.get("identity_confidence", 0.0) or 0.0))), "freshness_seconds": _bounded_int(observed.get("freshness_seconds"), 31536000)},
        "event": event,
        "policy": {"action": str(policy.get("action") or "log_only"), "rule_id": str(policy.get("rule_id") or ""), "policy_version": str(policy.get("policy_version") or ""), "policy_hash": _policy_hash(policy), "reason_code": str(policy.get("reason_code") or "NO_MATCH"), "human_review_required": bool(policy.get("human_review_required", False))},
        "enforcement": {"requested": bool(enforcement), "action": str(enforcement.get("action") or "none"), "status": str(enforcement.get("status") or "not_requested"), "target_ref": opaque_ref(enforcement["target_ref"], key=ref_key) if enforcement.get("target_ref") else None, "adapter_ref": opaque_ref(enforcement["adapter_ref"], key=ref_key) if enforcement.get("adapter_ref") else None, "idempotency_ref": opaque_ref(enforcement["idempotency_ref"], key=ref_key) if enforcement.get("idempotency_ref") else None, "error_code": enforcement.get("error_code")},
        "privacy": {"redacted": True, "redaction_version": "network-pii-1", "redaction_proof": "", "omitted_fields": ["raw_ip", "raw_mac", "raw_domain", "raw_url", "payload", "username", "certificate_subject"]},
        "delivery": {"queued": True, "acknowledged": bool(acknowledged), "attempt": _bounded_int(observed.get("attempt"), 100000), "loss_count": _bounded_int(loss_count, 9223372036854775807), "delivery_id": event_id},
    }
    proof = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload["privacy"]["redaction_proof"] = "sha256:" + hashlib.sha256(proof).hexdigest()
    validate_network_event(payload)
    assert_safe_network_payload(payload)
    return payload


def validate_network_event(payload: Mapping[str, Any]) -> None:
    errors = sorted(_VALIDATOR.iter_errors(payload), key=lambda error: list(error.path))
    if errors:
        raise NetworkContractError("invalid Shield network event: " + "; ".join(error.message for error in errors[:3]))


def assert_safe_network_payload(payload: Mapping[str, Any]) -> None:
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    if _SECRET.search(serialized) or _EMAIL.search(serialized) or _RAW_IP.search(serialized):
        raise NetworkContractError("network payload contains secret, email, or raw IPv4 address")
    if len(serialized.encode("utf-8")) > 64 * 1024:
        raise NetworkContractError("network payload exceeds 64 KiB")


__all__ = ["NetworkContractError", "SCHEMA", "VERSION", "assert_safe_network_payload", "build_network_event", "opaque_ref", "validate_network_event"]
