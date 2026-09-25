"""Validated tenant settings shared by the control plane and enrolled agents."""

from __future__ import annotations

import hashlib
import json
from typing import Any


SETTING_RULES: dict[str, tuple[type, set[Any] | None]] = {
    "containmentMode": (str, {"autonomous", "approval", "audit", "lockdown"}),
    "governanceTier": (str, {"tier1", "tier2"}),
    "ringBufferInterval": (str, {"25", "50", "100"}),
    "retentionDays": (str, {"30", "90", "365", "indefinite"}),
    "approvalThreshold": (int, None),
    "containmentCooldown": (int, None),
    "sensorCadence": (str, {"25", "50", "100"}),
    "evidenceDestination": (str, {"integrity", "siem", "both"}),
    "evidenceRetention": (int, None),
    "smtpPort": (str, None),
    "smtpHost": (str, None),
    "smtpRecipient": (str, None),
    "realOnly": (bool, None),
    "notifyContain": (bool, None),
    "notifyDeny": (bool, None),
    "notifySensorDrop": (bool, None),
    "sensorProcess": (bool, None),
    "sensorFile": (bool, None),
    "sensorNetwork": (bool, None),
    "autoReconnect": (bool, None),
    "autoContain": (bool, None),
    "humanApproval": (bool, None),
    "evidenceAutoRetry": (bool, None),
    "guardrailToolCalls": (bool, None),
    "guardrailModelRouting": (bool, None),
    "guardrailRetrieval": (bool, None),
    "guardrailOutputChecks": (bool, None),
    "guardrailPostAction": (bool, None),
    # Hermes is a downstream, analysis-only consumer. Key material remains host-managed.
    "hermesEnabled": (bool, None),
    "hermesAgentId": (str, None),
    "hermesTransport": (str, {"local-spool"}),
    "hermesAnalysisOnly": (bool, None),
    "hermesRedactionMode": (str, {"strict"}),
    "hermesEventScope": (str, {"all", "decisions", "network"}),
    "hermesSpoolPath": (str, None),
    "hermesKeyPath": (str, None),
    "hermesMaxBatch": (int, None),
    "hermesSpoolMaxBytes": (int, None),
    "hermesAutoRetry": (bool, None),
}


def validate_settings(settings: dict[str, Any]) -> dict[str, Any]:
    """Return a canonical settings copy or raise a precise validation error."""
    if not isinstance(settings, dict):
        raise ValueError("settings must be an object")
    unknown = sorted(set(settings) - set(SETTING_RULES))
    if unknown:
        raise ValueError(f"unknown setting(s): {unknown}")
    result: dict[str, Any] = {}
    for key, value in settings.items():
        expected, choices = SETTING_RULES[key]
        valid_type = isinstance(value, expected) if expected is bool else (isinstance(value, expected) and not isinstance(value, bool))
        if not valid_type:
            raise ValueError(f"{key} must be a {expected.__name__}")
        if choices is not None and value not in choices:
            raise ValueError(f"{key} must be one of {sorted(choices)}")
        if key == "approvalThreshold" and not 0 <= value <= 100:
            raise ValueError("approvalThreshold must be between 0 and 100")
        if key in {"containmentCooldown", "evidenceRetention"} and value < 0:
            raise ValueError(f"{key} must be non-negative")
        if key == "hermesAnalysisOnly" and value is not True:
            raise ValueError("hermesAnalysisOnly must remain enabled")
        if key == "hermesAgentId" and len(value) > 256:
            raise ValueError("hermesAgentId must be at most 256 characters")
        if key in {"hermesSpoolPath", "hermesKeyPath"} and len(value) > 512:
            raise ValueError(f"{key} must be at most 512 characters")
        if key == "hermesMaxBatch" and not 1 <= value <= 10:
            raise ValueError("hermesMaxBatch must be between 1 and 10")
        if key == "hermesSpoolMaxBytes" and not 65536 <= value <= 16 * 1024 * 1024:
            raise ValueError("hermesSpoolMaxBytes must be between 65536 and 16777216")
        result[key] = value
    return result


def settings_version(settings: dict[str, Any]) -> str:
    canonical = json.dumps(settings, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


__all__ = ["SETTING_RULES", "settings_version", "validate_settings"]
