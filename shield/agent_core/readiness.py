"""Evidence-backed production gates for responder capabilities.

The gate is intentionally explicit: a boolean flag alone must never turn on a
destructive responder. Each capability needs the proofs appropriate to its
runtime boundary, and the serialized status is safe to publish to operators.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Mapping


BASE_PROOFS = (
    "policy_signature_verified",
    "agent_identity_verified",
    "kernel_probe_verified",
    "audit_receipt_verified",
    "rollback_verified",
    "operator_approval",
)

ACTION_PROOFS = {
    "kill_process": BASE_PROOFS + ("kill_runtime_tested",),
    "freeze_cgroup": BASE_PROOFS + ("cgroup_runtime_tested",),
    "block_flow": BASE_PROOFS + ("network_runtime_tested",),
}


@dataclass(frozen=True)
class ProductionReadiness:
    """Immutable proof set used to decide whether a responder may be enabled."""

    proofs: Mapping[str, bool]
    details: Mapping[str, str] | None = None

    @classmethod
    def from_mapping(cls, proofs: Mapping[str, Any] | None = None, *, details: Mapping[str, str] | None = None) -> "ProductionReadiness":
        values = {key: bool((proofs or {}).get(key, False)) for key in set(BASE_PROOFS) | {item for keys in ACTION_PROOFS.values() for item in keys}}
        return cls(values, details or {})

    @classmethod
    def from_artifact(
        cls,
        path: str | Path,
        *,
        device_id: str,
        max_age_seconds: int = 86_400,
        now: datetime | None = None,
        require_root_owner: bool = False,
    ) -> "ProductionReadiness":
        """Load a device-bound, time-bounded proof artifact."""
        artifact_path = Path(path)
        stat = artifact_path.stat()
        if stat.st_mode & 0o022:
            raise ValueError("responder readiness artifact must not be group/other writable")
        if require_root_owner and stat.st_uid != 0:
            raise ValueError("responder readiness artifact must be owned by root")
        if max_age_seconds <= 0:
            raise ValueError("responder proof max age must be positive")
        payload = json.loads(artifact_path.read_text(encoding="utf-8"))
        if payload.get("schema") != "xibalba.responder-readiness.v1":
            raise ValueError("unsupported responder readiness artifact schema")
        if payload.get("device_id") != device_id:
            raise ValueError("responder readiness artifact is for a different device")
        generated_at = datetime.fromisoformat(str(payload.get("generated_at", "")).replace("Z", "+00:00"))
        reference = now or datetime.now(timezone.utc)
        if generated_at.tzinfo is None:
            raise ValueError("responder readiness generated_at must include a timezone")
        age = (reference - generated_at).total_seconds()
        if age < -300 or age > max_age_seconds:
            raise ValueError("responder readiness artifact is expired or from the future")
        return cls.from_mapping(payload.get("proofs"), details=payload.get("details"))

    def missing(self, action: str) -> list[str]:
        required = ACTION_PROOFS.get(action, BASE_PROOFS)
        return [key for key in required if not self.proofs.get(key, False)]

    def allowed(self, action: str) -> bool:
        return not self.missing(action)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ready": {action: self.allowed(action) for action in ACTION_PROOFS},
            "proofs": dict(self.proofs),
            "missing": {action: self.missing(action) for action in ACTION_PROOFS},
            "details": dict(self.details or {}),
        }


__all__ = ["ProductionReadiness", "BASE_PROOFS", "ACTION_PROOFS"]
