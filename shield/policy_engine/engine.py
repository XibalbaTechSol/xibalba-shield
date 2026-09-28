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
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Mapping
from urllib.error import URLError
from urllib.request import Request, urlopen

from integrity_sdk.core.decision import DENY, ENFORCE, LOG_ONLY, PERMIT, resolve as resolve_decision

from ..opa_client import evaluate as opa_evaluate, OPAUnavailableError

from ..schemas.events import (
    Decision,
    EventRef,
    NormalizedEvent,
    PolicyRef,
    PolicyDecision,
    RuleRef,
)
from .risk import assess_event

logger = logging.getLogger("shield.policy_engine")

# docs/EXECUTION_PLAN.md A3 "permit means permitted": this pack's own per-event-class
# no-match default, passed to `integrity_sdk.core.decision.resolve()`. Device sensor
# classes stay `log_only` (today's existing behavior, unchanged); `agent_event` also
# stays `log_only` here -- REGULATED_EVENT_DEFAULTS below is the one profile the plan
# names explicitly ("hipaa agent tool calls deny").
DEFAULT_EVENT_DEFAULTS: Mapping[str, str] = {
    "process_activity": LOG_ONLY,
    "file_activity": LOG_ONLY,
    "network_flow": LOG_ONLY,
    "agent_event": LOG_ONLY,
}

REGULATED_EVENT_DEFAULTS: Mapping[str, str] = {
    **DEFAULT_EVENT_DEFAULTS,
    "agent_event": DENY,
}

# Keyed the same as shield/opa_local.py's PROFILES -- the one place a compliance vertical's
# name already exists in this repo -- so DeviceConfig.policy_profile (config/loader.py) has
# a single source of truth for which event_defaults a `shield run` deployment gets, instead
# of a second hardcoded profile-name list drifting from the first.
EVENT_DEFAULTS_BY_PROFILE: Mapping[str, Mapping[str, str]] = {
    "smb": DEFAULT_EVENT_DEFAULTS,
    "professional-services": DEFAULT_EVENT_DEFAULTS,
    "regulated": REGULATED_EVENT_DEFAULTS,
}


def event_defaults_for_profile(profile: str) -> Mapping[str, str]:
    """`profile` is `DeviceConfig.policy_profile` -- "" (not set) or an unrecognized value
    both fall back to `DEFAULT_EVENT_DEFAULTS`, today's existing behavior, rather than
    raising: an operator who never set this new field must see no behavior change."""
    return EVENT_DEFAULTS_BY_PROFILE.get(profile, DEFAULT_EVENT_DEFAULTS)

# Reason-code substrings that distinguish Shield's finer-grained enforcement actions from
# a plain `deny` under the coarser 3-way decision contract (permit/deny/log_only) -- see
# `_translate_decision`'s docstring for why this mapping exists at all.
_CONTAIN_MARKER = "_CONTAIN_"
_ESCALATE_MARKER = "_ESCALATE_"


def _translate_decision(resolved_decision: str, reason_code: str) -> str:
    """Map the SDK's 3-way decision contract (permit/deny/log_only) back onto Shield's own
    5-way `Decision.action` vocabulary (allow/deny/contain/log_only/escalate) -- that
    vocabulary is Shield's canonical, frozen output shape (spec/xibalba-shield-v1.md §5.5)
    consumed by `agent_core/router.py` (real containment/escalation handling), SIEM
    exports, and every existing test; it does not change here.

    `contain` and `escalate` are still `deny`-shaped under the coarser contract (both stop
    the action in `router.py`'s enforcement flow -- see that module's own observe-mode gate,
    which treats `deny`/`contain`/`escalate` identically), so the reason code a matching
    Rego rule declares is what recovers the finer distinction Shield's real enforcement
    still needs.
    """
    if resolved_decision == PERMIT:
        return "allow"
    if resolved_decision == LOG_ONLY:
        return "log_only"
    # resolved_decision == DENY
    if _CONTAIN_MARKER in reason_code:
        return "contain"
    if _ESCALATE_MARKER in reason_code:
        return "escalate"
    return "deny"

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

    def __init__(
        self, opa_url: str = "http://localhost:8181", opa_package_path: str = "/v1/data/shield/policy", *,
        policy_version: str = "", policy_hash: str = "", event_defaults: Mapping[str, str] = DEFAULT_EVENT_DEFAULTS,
    ):
        self.opa_url = opa_url
        self.opa_package_path = opa_package_path
        self.policy_version = policy_version
        self.policy_hash = policy_hash
        self.event_defaults = event_defaults
        self._opa_healthy: bool | None = None
        self._last_opa_check_at: str | None = None
        self._last_opa_error: str | None = None

    def health_status(self) -> dict[str, str | bool | None]:
        """Return advisory runtime health from the most recent policy evaluation.

        This never participates in an enforcement decision; evaluation still fails closed
        when OPA is unavailable.
        """
        return {
            "opa_url": self.opa_url,
            "healthy": self._opa_healthy,
            "last_checked_at": self._last_opa_check_at,
            "last_error": self._last_opa_error,
        }

    def probe(self, timeout: float = 0.5) -> dict[str, str | bool | None]:
        """Active OPA health check, independent of `evaluate()` traffic. Without this,
        `health_status()` only reflects the last real evaluation -- on an idle sensor
        stream (no events, so no `evaluate()` calls) that value is frozen and can read
        stale-healthy indefinitely. Hits OPA's own `/health` endpoint directly, the same
        one `OpaSupervisor._healthy_probe` already uses, so this works whether or not
        Shield itself supervises the OPA process."""
        try:
            request = Request(f"{self.opa_url.rstrip('/')}/health", method="GET")
            with urlopen(request, timeout=timeout) as response:
                self._opa_healthy = 200 <= getattr(response, "status", 200) < 300
                self._last_opa_error = None if self._opa_healthy else f"HTTP {response.status}"
        except (OSError, URLError) as exc:
            self._opa_healthy = False
            self._last_opa_error = str(exc)
        self._last_opa_check_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        return self.health_status()

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
            self._opa_healthy = True
            self._last_opa_check_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            self._last_opa_error = None
            raw = opa_decision.raw_result

            # `decision`/`reason_code` are present only when a rule actually matched (see
            # shield/policies/rego/*.rego -- deliberately no `default` for either), which is
            # what lets `resolve()` distinguish "a rule matched" from "nothing matched, apply
            # this pack's per-event-class default" (docs/EXECUTION_PLAN.md A3 "permit means
            # permitted"). `mode=ENFORCE` here is Shield's own OPA-evaluation step; the
            # separate observe/enforce posture `router.py` applies afterward is unrelated.
            raw_decision = (
                {"decision": raw.get("decision"), "reason_code": raw.get("reason_code"), "controls": raw.get("controls", [])}
                if "decision" in raw and "reason_code" in raw else None
            )
            resolved = resolve_decision(event.klass, raw_decision, event_defaults=self.event_defaults, mode=ENFORCE)
            action = _translate_decision(resolved.decision, resolved.reason_code)

            # rule_id/name/version/message stay sourced from the legacy Rego vars (unchanged,
            # still accurate) -- they're Shield-local display/audit metadata, not part of the
            # C3 contract's strict {"decision","reason_code","controls"} result shape.
            rule_id = raw.get("rule_id", "_no_match")
            name = raw.get("name", "No rule matched")
            version = raw.get("version", "0")
            reason = (
                raw.get("message", "matched with no action defined") if raw_decision is not None
                else f"no policy rule matched; pack default for {event.klass}: {resolved.decision} ({resolved.reason_code})"
            )

            assessment = assess_event(event)
            # OPA remains authoritative for explicit deny/contain decisions.  The
            # local assessment may only harden an otherwise permissive result when
            # observable evidence crosses the containment threshold.
            if action in {"allow", "log_only"} and assessment.suggested_action == "contain":
                action = "contain"
                reason = "local risk gate: " + "; ".join(signal.reason for signal in assessment.signals)
                rule_id = "_local-risk-containment"
                name = "High-confidence local risk evidence"
                version = "1.0.0"
            elif action in {"allow", "log_only"} and assessment.suggested_action == "escalate":
                action = "escalate"
                reason = "local risk gate requires review: " + "; ".join(signal.reason for signal in assessment.signals)
                rule_id = "_local-risk-review"
                name = "Local risk evidence requires review"

            # An explicit OPA enforcement verdict is itself high-quality evidence,
            # even when the normalized event has no optional risk fields populated.
            # Do not report a policy deny as confidence=0 merely because the risk
            # enrichment layer had nothing additional to score.
            decision_confidence = assessment.confidence
            decision_human_required = assessment.human_required
            decision_evidence = [signal.reason for signal in assessment.signals]
            if action == "contain":
                decision_confidence = max(decision_confidence, 0.95)
                decision_human_required = False
                decision_evidence.append(f"OPA enforcement rule: {rule_id}")
            elif action == "deny":
                decision_confidence = max(decision_confidence, 0.90)
                decision_human_required = False
                decision_evidence.append(f"OPA denial rule: {rule_id}")
            elif action == "escalate":
                decision_confidence = max(decision_confidence, 0.75)
                decision_evidence.append(f"OPA escalation rule: {rule_id}")
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
                    confidence=decision_confidence,
                    risk_score=assessment.score,
                    human_required=decision_human_required,
                    evidence=decision_evidence,
                ),
            )
        except OPAUnavailableError as exc:
            self._opa_healthy = False
            self._last_opa_check_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            self._last_opa_error = str(exc)
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
