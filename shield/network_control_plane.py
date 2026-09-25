"""Composition root for local network observation, policy, and telemetry."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .network_adapters import AdapterResult, NetworkActionExecutor
from .network_ingestion import NetworkEventIngestor
from .network_policy import NetworkActionRequest, NetworkGateConfig, NetworkIdentity, authorize_network_action
from .network_policy_engine import NetworkPolicyDecision, NetworkPolicyEngine


@dataclass(frozen=True)
class NetworkControlPlaneResult:
    delivery_id: str | None
    decision: NetworkPolicyDecision


@dataclass(frozen=True)
class NetworkEnforcementResult:
    delivery_id: str | None
    policy_decision: NetworkPolicyDecision
    gate_decision: Any
    adapter_result: AdapterResult


class NetworkControlPlane:
    """Evaluate locally before enqueueing; Hermes is not on the decision path."""

    def __init__(self, *, policy_engine: NetworkPolicyEngine, ingestor: NetworkEventIngestor, action_executor: NetworkActionExecutor | None = None, gate_config: NetworkGateConfig = NetworkGateConfig()) -> None:
        self.policy_engine = policy_engine
        self.ingestor = ingestor
        self.action_executor = action_executor
        self.gate_config = gate_config

    def handle(self, observed: Mapping[str, Any], *, enforcement: Mapping[str, Any] | None = None, **identity: Any) -> NetworkControlPlaneResult:
        decision = self.policy_engine.evaluate(observed)
        policy = {
            "action": decision.action,
            "rule_id": decision.rule_id,
            "policy_version": decision.policy_version,
            "policy_hash": decision.policy_hash,
            "reason_code": decision.reason_code,
            "human_review_required": decision.human_review_required,
        }
        delivery_id = self.ingestor.ingest(observed, policy=policy, enforcement=enforcement, **identity)
        return NetworkControlPlaneResult(delivery_id, decision)

    def enforce(
        self,
        observed: Mapping[str, Any],
        request: NetworkActionRequest,
        identity: NetworkIdentity,
        *,
        adapter_ref: str,
        **event_identity: Any,
    ) -> NetworkEnforcementResult:
        """Authorize and execute locally, then durably record the adapter outcome.

        This path is intentionally independent of Hermes and Cortex. A missing executor or a
        denied/stale identity produces a failed local result and never invokes an adapter.
        """
        if self.action_executor is None:
            raise RuntimeError("local network action executor is not configured")
        policy_decision = self.policy_engine.evaluate(observed)
        gate_decision = authorize_network_action(identity, request, config=self.gate_config)
        try:
            adapter_result = self.action_executor.apply(request, gate_decision, adapter_ref=adapter_ref)
        except Exception as exc:  # noqa: BLE001 - surface adapter failures as bounded telemetry
            adapter_result = AdapterResult(request.action, "failed", adapter_ref, request.idempotency_ref, error_code=str(exc)[:160])
        policy = {
            "action": policy_decision.action,
            "rule_id": policy_decision.rule_id,
            "policy_version": policy_decision.policy_version,
            "policy_hash": policy_decision.policy_hash,
            "reason_code": policy_decision.reason_code,
            "human_review_required": policy_decision.human_review_required,
        }
        enforcement = {
            "action": adapter_result.action,
            "status": adapter_result.status,
            "target_ref": request.target_ref,
            "adapter_ref": adapter_result.adapter_ref,
            "idempotency_ref": adapter_result.idempotency_ref,
            "error_code": adapter_result.error_code,
        }
        delivery_id = self.ingestor.ingest(observed, policy=policy, enforcement=enforcement, **event_identity)
        return NetworkEnforcementResult(delivery_id, policy_decision, gate_decision, adapter_result)


__all__ = ["NetworkControlPlane", "NetworkControlPlaneResult", "NetworkEnforcementResult"]
