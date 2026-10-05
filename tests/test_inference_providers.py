from __future__ import annotations

from integrity_sdk.core.decision_trace import DecisionEnvelope

from shield.policy_engine.inference import LocalClassifierProvider, build_inference_provider


def _envelope(severity: str = "high") -> DecisionEnvelope:
    return DecisionEnvelope(
        tenant_id="tenant-a", agent_id="agent-a", trace_id="trace-a", event_id="event-a",
        event_type="shield.policy_decision", timestamp="2026-10-04T00:00:00Z",
        policy_decision="deny", metadata={"severity": severity, "event_class": "agent_event"},
    )


def test_jev_provider_is_selectable_without_network():
    config, provider = build_inference_provider({"inferenceEnabled": True, "inferenceProvider": "jev"})
    assert config.provider == "jev"
    assert provider is not None
    assert provider.analyze(_envelope()).status == "available"


def test_local_classifier_is_selectable_and_advisory():
    config, provider = build_inference_provider({"inferenceEnabled": True, "inferenceProvider": "local_classifier"})
    assert config.provider == "local_classifier"
    assert isinstance(provider, LocalClassifierProvider)
    result = provider.analyze(_envelope())
    assert result.recommended_escalation is True
    assert result.causal_claim is False


def test_remote_providers_require_explicit_endpoint():
    for name in ("lila", "llm"):
        try:
            build_inference_provider({"inferenceEnabled": True, "inferenceProvider": name})
        except ValueError as exc:
            assert "inferenceEndpoint" in str(exc)
        else:
            raise AssertionError(f"{name} provider accepted without endpoint")
