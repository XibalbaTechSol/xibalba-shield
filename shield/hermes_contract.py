"""Privacy-preserving, versioned Shield -> Hermes event contract.

This boundary deliberately exports an allowlist of bounded metadata only. Local Shield policy
and enforcement remain authoritative; Hermes receives untrusted observations and outcomes.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker

from .schemas.events import AgentEvent, FileActivity, NetworkFlow, NormalizedEvent, ProcessActivity, PolicyDecision

SCHEMA_NAME = "xibalba.shield.hermes.event"
SCHEMA_VERSION = "1.0.0"
SCHEMA_PATH = Path(__file__).with_name("schemas") / "xibalba.shield.hermes.event.schema.json"
_SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
_VALIDATOR = Draft202012Validator(_SCHEMA, format_checker=FormatChecker())
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_SECRET = re.compile(r"(?i)(bearer\s+[A-Za-z0-9._~+/=-]+|(?:sk|pk|ghp|xoxb|xapp)-[A-Za-z0-9_-]{12,}|password\s*[:=]\s*[^\s,;]+|private[_ -]?key\s*[:=]\s*[^\s,;]+)")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_HOME_PATH = re.compile(r"/(?:home|Users)/[^\s\"']+")


class HermesContractError(ValueError):
    """Raised when a producer or consumer attempts to cross the contract unsafely."""


def _hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _path_class(path: str) -> str:
    if not path:
        return "unknown"
    if path.startswith(("/usr/", "/bin/", "/sbin/", "/lib/", "/opt/")):
        return "system"
    if path.startswith(("/home/", "/Users/")):
        return "user-home"
    if path.startswith(("/tmp/", "/var/tmp/")):
        return "temporary"
    if path.startswith(("/run/", "/var/run/")):
        return "runtime"
    return "other"


def _ip_scope(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "unknown"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_private:
        return "private"
    return "public"


def _iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _event_view(event: NormalizedEvent | Mapping[str, Any]) -> tuple[dict[str, Any], str, str]:
    raw = event.to_dict() if hasattr(event, "to_dict") else dict(event)
    klass = str(raw.get("class") or "unknown")
    action = "observed"
    activity = raw.get("activity") if isinstance(raw.get("activity"), Mapping) else {}
    if isinstance(activity, Mapping):
        action = str(activity.get("type") or action)[:64]
    view: dict[str, Any] = {"class": klass, "action": action, "severity": str(activity.get("severity", "low")), "risk_score": 0.0, "confidence": 0.0}
    process = raw.get("process")
    if isinstance(process, Mapping):
        path = str(process.get("exe_path") or "")
        view["process"] = {
            "pid": max(0, int(process.get("pid") or 0)), "ppid": max(0, int(process.get("ppid") or 0)),
            "name": str(process.get("name") or "")[:128], "parent_name": str(process.get("parent_name") or "")[:128],
            "path_class": _path_class(path), "path_hash": _hash(path) if path else None,
            "hash_sha256": process.get("hash_sha256") if _SHA256.fullmatch(str(process.get("hash_sha256") or "")) else None,
        }
    file_info = raw.get("file")
    if isinstance(file_info, Mapping):
        path = str(file_info.get("path") or "")
        view["file"] = {"name": str(file_info.get("name") or "")[:128], "ext": str(file_info.get("ext") or "")[:32], "path_class": _path_class(path), "path_hash": _hash(path) if path else None}
    flow = raw.get("flow")
    if isinstance(flow, Mapping):
        view["network"] = {"source_scope": _ip_scope(str(flow.get("src_ip") or "")), "destination_scope": _ip_scope(str(flow.get("dst_ip") or "")), "src_port": int(flow.get("src_port") or 0), "dst_port": int(flow.get("dst_port") or 0), "protocol": str(flow.get("protocol") or "")[:16], "direction": str(flow.get("direction") or "outbound")}
    agent = raw.get("agent")
    context = raw.get("context")
    if isinstance(agent, Mapping):
        context = context if isinstance(context, Mapping) else {}
        view["agent"] = {"agent_ref": _hash(agent.get("agent_id", "")), "type": str(agent.get("type") or "")[:64], "data_source_count": min(1000, len(context.get("data_sources") or [])), "tool_count": min(1000, len(context.get("tools_called") or []))}
    return view, str(raw.get("device_id") or ""), str(raw.get("tenant_id") or "")


def _reason_code(decision: Mapping[str, Any]) -> str:
    reason = str(decision.get("reason") or "").lower()
    if "opa" in reason and "unavail" in reason:
        return "OPA_UNAVAILABLE"
    if "risk" in reason:
        return "LOCAL_RISK_GATE"
    if decision.get("rule_id") or decision.get("rule"):
        return "RULE_MATCH"
    return "NO_MATCH"


def build_event(event: NormalizedEvent | Mapping[str, Any], decision: PolicyDecision | Mapping[str, Any], *, device_role: str = "workstation", sensor: str = "unknown", transport: str = "local-spool", enforcement: Mapping[str, Any] | None = None, delivery_id: str | None = None, attempt: int = 0, acknowledged: bool = False) -> dict[str, Any]:
    event_view, device_id, tenant_id = _event_view(event)
    raw_decision = decision.to_dict() if hasattr(decision, "to_dict") else dict(decision)
    decision_body = raw_decision.get("decision") if isinstance(raw_decision.get("decision"), Mapping) else raw_decision
    rule = raw_decision.get("rule") if isinstance(raw_decision.get("rule"), Mapping) else {}
    policy = raw_decision.get("policy") if isinstance(raw_decision.get("policy"), Mapping) else {}
    event_id = str((raw_decision.get("event_ref") or {}).get("event_id") or raw_decision.get("event_id") or _hash(json.dumps(event_view, sort_keys=True)))
    payload: dict[str, Any] = {
        "schema": SCHEMA_NAME, "schema_version": SCHEMA_VERSION, "event_id": event_id,
        "emitted_at": _iso_now(), "observed_at": str((event.to_dict() if hasattr(event, "to_dict") else event).get("time") or _iso_now()),
        "device": {"device_id": device_id, "tenant_id": tenant_id, "role": device_role},
        "source": {"component": "shield", "sensor": sensor, "transport": transport}, "event": event_view,
        "policy": {"action": str(decision_body.get("action") or "log_only"), "rule_id": str(rule.get("rule_id") or ""), "rule_name": str(rule.get("name") or ""), "policy_version": str(policy.get("version") or ""), "policy_hash": str(policy.get("hash") or "sha256:" + "0" * 64), "reason_code": _reason_code(decision_body), "human_review_required": bool(decision_body.get("human_required", False))},
        "enforcement": {"requested": bool(enforcement), "action": str((enforcement or {}).get("action") or "none"), "status": str((enforcement or {}).get("status") or "not_requested"), "target_ref": _hash((enforcement or {}).get("target_ref")) if (enforcement or {}).get("target_ref") else None, "error_code": (enforcement or {}).get("error_code")},
        "privacy": {"redaction_version": "pii-redaction-1", "redacted": True, "redaction_proof": "", "omitted_fields": ["cmdline", "raw_path", "environment", "prompts", "model_output", "raw_network_payload"]},
        "delivery": {"local_logged": True, "queued": True, "delivery_id": delivery_id or event_id, "acknowledged": bool(acknowledged), "attempt": max(0, int(attempt))},
    }
    proof_input = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload["privacy"]["redaction_proof"] = "sha256:" + hashlib.sha256(proof_input).hexdigest()
    validate_event(payload)
    assert_safe_payload(payload)
    return payload


def validate_event(payload: Mapping[str, Any]) -> None:
    errors = sorted(_VALIDATOR.iter_errors(payload), key=lambda error: list(error.path))
    if errors:
        raise HermesContractError("invalid Shield-Hermes event: " + "; ".join(error.message for error in errors[:3]))


def assert_safe_payload(payload: Mapping[str, Any]) -> None:
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    if _SECRET.search(serialized) or _EMAIL.search(serialized) or _HOME_PATH.search(serialized):
        raise HermesContractError("outbound Shield-Hermes payload contains a secret, email, or raw home path")
    if len(serialized.encode("utf-8")) > 64 * 1024:
        raise HermesContractError("outbound Shield-Hermes payload exceeds 64 KiB")


__all__ = ["HermesContractError", "SCHEMA_NAME", "SCHEMA_VERSION", "assert_safe_payload", "build_event", "validate_event"]
