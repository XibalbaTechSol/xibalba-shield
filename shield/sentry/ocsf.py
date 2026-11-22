"""
Phase 3: Open Cybersecurity Schema Framework (OCSF) Class 6003 SIEM Integration.

Serializes AI security events to the OCSF v1.2+ Class 6003 (AI/ML Activity) standard,
enabling native, turn-key integration with Enterprise SIEM/SOAR platforms
(Splunk, Elastic SIEM, Datadog, Chronicle, Sentinel).
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from enum import IntEnum
from typing import Any, Mapping, Sequence


class OCSFActivityId(IntEnum):
    UNKNOWN = 0
    INPUT_INGEST = 1          # Data ingress / prompt input processing
    MODEL_INFERENCE = 2       # LLM generation / reasoning trajectory
    TOOL_GATED = 3            # Proof-of-Justification tool execution attempt
    CANARY_TRIP = 4           # Canary trap triggered (exfiltration attempt)
    POLICY_VIOLATION = 5      # Taint / safety violation (unauthorized action blocked)


class OCSFSeverityId(IntEnum):
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass(frozen=True)
class OCSFEvent:
    class_uid: int
    class_name: str
    category_uid: int
    category_name: str
    activity_id: int
    activity_name: str
    severity_id: int
    severity: str
    time: int
    metadata: dict[str, Any]
    actor: dict[str, Any]
    ai_activity: dict[str, Any]
    unmapped: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


class OCSFEventBuilder:
    """Constructs compliant OCSF Class 6003 events for AI agent defense."""

    CLASS_UID = 6003
    CLASS_NAME = "AI Activity"
    CATEGORY_UID = 6
    CATEGORY_NAME = "Application Activity"
    VERSION = "1.2.0"

    @classmethod
    def build_event(
        cls,
        *,
        activity_id: OCSFActivityId,
        severity_id: OCSFSeverityId,
        tenant_id: str,
        agent_did: str,
        user_id: str = "",
        device_id: str = "",
        tool_name: str = "",
        model_name: str = "",
        taint_level: str = "",
        message: str = "",
        details: Mapping[str, Any] | None = None,
    ) -> OCSFEvent:
        now_sec = int(time.time())
        details_dict = dict(details or {})

        activity_name_map = {
            OCSFActivityId.INPUT_INGEST: "Input Ingest",
            OCSFActivityId.MODEL_INFERENCE: "Model Inference",
            OCSFActivityId.TOOL_GATED: "Tool Gated Execution",
            OCSFActivityId.CANARY_TRIP: "Canary Trap Detection",
            OCSFActivityId.POLICY_VIOLATION: "AI Policy Violation",
        }

        severity_name_map = {
            OCSFSeverityId.INFORMATIONAL: "Informational",
            OCSFSeverityId.LOW: "Low",
            OCSFSeverityId.MEDIUM: "Medium",
            OCSFSeverityId.HIGH: "High",
            OCSFSeverityId.CRITICAL: "Critical",
        }

        metadata = {
            "version": cls.VERSION,
            "product": {
                "name": "Xibalba Shield",
                "vendor_name": "Xibalba Solutions LLC",
                "version": "1.0.0",
            },
            "tenant_id": tenant_id,
            "log_name": "shield.sentry.ai_activity",
        }

        actor = {
            "id": agent_did,
            "type": "AI Agent",
            "user": {"name": user_id or "autonomous_agent"},
            "device": {"id": device_id or "shield-node"},
        }

        ai_activity = {
            "model_name": model_name or "claude-3-7-sonnet",
            "operation": tool_name or activity_name_map.get(activity_id, "unknown"),
            "taint_level": taint_level,
            "message": message,
        }

        return OCSFEvent(
            class_uid=cls.CLASS_UID,
            class_name=cls.CLASS_NAME,
            category_uid=cls.CATEGORY_UID,
            category_name=cls.CATEGORY_NAME,
            activity_id=int(activity_id),
            activity_name=activity_name_map.get(activity_id, "Unknown"),
            severity_id=int(severity_id),
            severity=severity_name_map.get(severity_id, "Informational"),
            time=now_sec,
            metadata=metadata,
            actor=actor,
            ai_activity=ai_activity,
            unmapped=details_dict,
        )

    @classmethod
    def export_jsonl(cls, events: Sequence[OCSFEvent | dict[str, Any]]) -> str:
        """Serializes a batch of OCSF events to standard JSONL."""
        lines = []
        for ev in events:
            if isinstance(ev, OCSFEvent):
                lines.append(ev.to_json())
            else:
                lines.append(json.dumps(ev, sort_keys=True))
        return "\n".join(lines) + ("\n" if lines else "")

    @classmethod
    def format_for_siem(
        cls,
        event: OCSFEvent | dict[str, Any],
        profile: str = "ocsf",
    ) -> dict[str, Any]:
        """Formats the event for specific SIEM intake profiles (Splunk, Elastic, Datadog)."""
        data = event.to_dict() if isinstance(event, OCSFEvent) else dict(event)
        if profile == "ocsf":
            return data
        if profile == "splunk":
            return {
                "time": data.get("time", int(time.time())),
                "source": "xibalba:shield:sentry",
                "sourcetype": "ocsf:ai_activity",
                "event": data,
            }
        if profile == "elastic":
            ecs = dict(data)
            ecs["@timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(data.get("time", int(time.time()))))
            ecs["ecs.version"] = "8.11.0"
            ecs["event.category"] = ["ai", "security"]
            return ecs
        if profile == "datadog":
            return {
                "ddsource": "xibalba-shield",
                "service": "agent-sentry",
                "message": data.get("ai_activity", {}).get("message", ""),
                "status": data.get("severity", "info").lower(),
                "ocsf": data,
            }
        return data
