"""
Policy Engine — spec/xibalba-shield-v1.md §4.3.

Evaluates normalized events (schemas/events.py) against OPA.
Every evaluation produces a PolicyDecision — matched or not, allowed or denied — mirroring
bcc_middleware's own posture in the parent repo (docs/INTERFACE_CONTRACT.md §7's
"no assume-success fallback"): `log_only` and `allow` are as visible in the audit trail
as a `deny`.

MUST be able to enforce with zero cloud round-trip (§4.3) — this module communicates with
a local sidecar OPA server, not a cloud service.
"""

from __future__ import annotations

import asyncio
import uuid
import logging
from dataclasses import dataclass, asdict

from integrity_sdk.policy.opa_client import evaluate as opa_evaluate, OPAUnavailableError

from ..schemas.events import (
    Decision,
    EventRef,
    NormalizedEvent,
    PolicyRef,
    PolicyDecision,
    RuleRef,
)

logger = logging.getLogger("shield.policy_engine")

def _event_severity(event: NormalizedEvent) -> str:
    activity = getattr(event, "activity", None)
    if activity is None:
        return "low"
    return getattr(activity, "severity", None) or getattr(activity, "risk_level", None) or "low"


@dataclass
class EvaluationContext:
    tenant_id: str = ""
    device_role: str = ""
    device_id: str = ""
    registered_agent_ids: frozenset[str] = frozenset()


class PolicyEngine:
    """Uses the SDK OPA client to evaluate rules."""

    def __init__(self, opa_url: str = "http://localhost:8181", opa_package_path: str = "/v1/data/shield/policy", *, policy_version: str = "", policy_hash: str = ""):
        self.opa_url = opa_url
        self.opa_package_path = opa_package_path
        self.policy_version = policy_version
        self.policy_hash = policy_hash

    def evaluate(self, event: NormalizedEvent, ctx: EvaluationContext) -> PolicyDecision:
        event_id = f"evt-{uuid.uuid4().hex[:12]}"
        
        # Build OPA input
        event_dict = asdict(event)
        ctx_dict = {
            "tenant_id": ctx.tenant_id,
            "device_role": ctx.device_role,
            "device_id": ctx.device_id,
            "registered_agent_ids": {aid: True for aid in ctx.registered_agent_ids}
        }
        opa_input = {
            "event": event_dict,
            "ctx": ctx_dict
        }

        try:
            opa_decision = asyncio.run(opa_evaluate(
                opa_url=self.opa_url,
                opa_package_path=self.opa_package_path,
                opa_timeout_seconds=2.0,
                opa_input=opa_input
            ))
            raw = opa_decision.raw_result
            
            # Extract fields expected by shield
            action = raw.get("action", "log_only")
            reason = raw.get("message", "matched with no action defined")
            rule_id = raw.get("rule_id", "_no_match")
            name = raw.get("name", "No rule matched")
            version = raw.get("version", "0")
            
            # If not allowed and no specific reason given by OPA, default to "deny" logic
            if not opa_decision.allow and action == "log_only":
                action = "deny"
                reason = "OPA denied the request"
                
            return PolicyDecision(
                device_id=ctx.device_id,
                invocation_id=getattr(event, "invocation_id", None) or str(uuid.uuid4()),
                event_ref=EventRef(klass=event.klass, event_id=event_id),
                rule=RuleRef(rule_id=rule_id, name=name, version=version),
                policy=PolicyRef(version=self.policy_version, hash=self.policy_hash),
                decision=Decision(
                    action=action,
                    reason=reason,
                    severity=_event_severity(event),
                ),
            )
        except OPAUnavailableError as exc:
            logger.error("OPA unavailable: %s", exc)
            # Fail closed as per spec
            return PolicyDecision(
                device_id=ctx.device_id,
                invocation_id=getattr(event, "invocation_id", None) or str(uuid.uuid4()),
                event_ref=EventRef(klass=event.klass, event_id=event_id),
                rule=RuleRef(rule_id="_opa_unavailable", name="OPA Unavailable", version="0"),
                policy=PolicyRef(version=self.policy_version, hash=self.policy_hash),
                decision=Decision(
                    action="deny",
                    reason=f"OPA unavailable: {exc}",
                    severity="high",
                ),
            )
