"""Local, deterministic authorization gate for bounded network actions.

This module only evaluates a request. It never invokes a firewall, DNS, NAC, switch, or
controller adapter. Hermes may request an action, but the local gate remains authoritative.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Literal

Action = Literal["block_flow", "block_domain", "isolate_device", "move_segment", "revoke_access", "rate_limit", "restore_access"]
Scope = Literal["device", "segment", "network"]
_REF = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class NetworkIdentity:
    device_ref: str
    source: str
    posture: str
    confidence: float
    freshness_seconds: int


@dataclass(frozen=True)
class NetworkActionRequest:
    action: Action
    target_ref: str
    scope: Scope = "device"
    duration_seconds: int = 0
    idempotency_ref: str = ""
    requested_by: str = "local-policy"
    approval_ref: str | None = None
    dry_run: bool = True
    affected_devices: int = 1
    affected_segments: int = 1

    def intent_hash(self) -> str:
        body = {"action": self.action, "target_ref": self.target_ref, "scope": self.scope, "duration_seconds": self.duration_seconds, "idempotency_ref": self.idempotency_ref}
        return "sha256:" + hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class NetworkGateConfig:
    min_confidence: float = 0.9
    max_identity_age_seconds: int = 900
    max_duration_seconds: int = 3600
    max_affected_devices: int = 1
    max_affected_segments: int = 1
    protected_refs: frozenset[str] = field(default_factory=frozenset)
    require_approval_for: frozenset[Action] = field(default_factory=lambda: frozenset({"isolate_device", "move_segment", "revoke_access", "restore_access"}))


@dataclass(frozen=True)
class NetworkGateDecision:
    allowed: bool
    status: str
    reason_code: str
    intent_hash: str


def authorize_network_action(identity: NetworkIdentity, request: NetworkActionRequest, config: NetworkGateConfig = NetworkGateConfig()) -> NetworkGateDecision:
    """Return a fail-closed decision with a stable reason code; no side effects occur."""
    intent_hash = request.intent_hash()
    def deny(code: str) -> NetworkGateDecision:
        return NetworkGateDecision(False, "denied", code, intent_hash)

    if not _REF.fullmatch(identity.device_ref) or not _REF.fullmatch(request.target_ref):
        return deny("OPAQUE_REFERENCE_REQUIRED")
    if request.idempotency_ref and not _REF.fullmatch(request.idempotency_ref):
        return deny("IDEMPOTENCY_REFERENCE_REQUIRED")
    if identity.posture != "known" or identity.source == "inferred":
        return deny("IDENTITY_NOT_AUTHORITATIVE")
    if identity.confidence < config.min_confidence:
        return deny("IDENTITY_CONFIDENCE_TOO_LOW")
    if identity.freshness_seconds < 0 or identity.freshness_seconds > config.max_identity_age_seconds:
        return deny("IDENTITY_STALE")
    if request.target_ref in config.protected_refs:
        return deny("PROTECTED_PATH")
    if request.affected_devices < 1 or request.affected_devices > config.max_affected_devices:
        return deny("BLAST_RADIUS_DEVICES")
    if request.affected_segments < 1 or request.affected_segments > config.max_affected_segments:
        return deny("BLAST_RADIUS_SEGMENTS")
    if request.scope != "device" and request.approval_ref is None:
        return deny("APPROVAL_REQUIRED_FOR_SCOPE")
    if request.action in config.require_approval_for and request.approval_ref is None:
        return deny("APPROVAL_REQUIRED")
    if request.duration_seconds < 0 or request.duration_seconds > config.max_duration_seconds:
        return deny("DURATION_OUT_OF_BOUNDS")
    if request.action in {"block_flow", "block_domain", "isolate_device", "move_segment", "rate_limit"} and request.duration_seconds == 0:
        return deny("EXPIRY_REQUIRED")
    if not request.idempotency_ref:
        return deny("IDEMPOTENCY_REQUIRED")
    if request.dry_run:
        return NetworkGateDecision(True, "preview", "DRY_RUN_APPROVED", intent_hash)
    return NetworkGateDecision(True, "approved", "LOCAL_POLICY_APPROVED", intent_hash)


__all__ = ["NetworkActionRequest", "NetworkGateConfig", "NetworkGateDecision", "NetworkIdentity", "authorize_network_action"]
