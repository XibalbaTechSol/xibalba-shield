"""Configurable, advisory inference providers for Shield.

Inference is deliberately downstream of deterministic policy evaluation. Providers receive a
redacted DecisionEnvelope only and return a JevAnalysis-shaped advisory. They cannot authorize,
contain, or rewrite the PolicyDecision.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from urllib.error import URLError
from urllib.request import Request, urlopen
from typing import Any, Mapping

from integrity_sdk.core.decision_trace import DecisionEnvelope, FixtureJevProvider, JevAnalysis, JevProvider


@dataclass(frozen=True)
class InferenceConfig:
    enabled: bool = False
    provider: str = "disabled"
    mode: str = "shadow"
    model: str = ""
    endpoint: str = ""
    prompt_profile: str = "shield-risk-v1"
    secret_ref: str = ""
    timeout_ms: int = 750
    max_tokens: int = 512
    temperature: float = 0.1
    redaction_mode: str = "strict"
    failure_mode: str = "continue_with_policy"
    event_classes: tuple[str, ...] = ()

    @classmethod
    def from_settings(cls, settings: Mapping[str, Any]) -> "InferenceConfig":
        provider = str(settings.get("inferenceProvider", "disabled"))
        enabled = bool(settings.get("inferenceEnabled", provider != "disabled")) and provider != "disabled"
        return cls(
            enabled=enabled,
            provider=provider,
            mode=str(settings.get("inferenceMode", "shadow")),
            model=str(settings.get("inferenceModel", "")),
            endpoint=str(settings.get("inferenceEndpoint", "")),
            prompt_profile=str(settings.get("inferencePromptProfile", "shield-risk-v1")),
            secret_ref=str(settings.get("inferenceSecretRef", "")),
            timeout_ms=int(settings.get("inferenceTimeoutMs", 750)),
            max_tokens=int(settings.get("inferenceMaxTokens", 512)),
            temperature=float(settings.get("inferenceTemperature", 0.1)),
            redaction_mode=str(settings.get("inferenceRedactionMode", "strict")),
            failure_mode=str(settings.get("inferenceFailureMode", "continue_with_policy")),
            event_classes=tuple(str(value) for value in settings.get("inferenceEventClasses", ())),
        )


class LocalClassifierProvider:
    provider_id = "shield.local-classifier.v1"

    def analyze(self, event: DecisionEnvelope) -> JevAnalysis:
        severity = str(event.metadata.get("severity", "low")).lower()
        high_risk = severity in {"high", "critical"} or event.metadata.get("event_class") in {"network_flow", "file_activity"} and severity == "medium"
        return JevAnalysis(self.provider_id, "available", severity if severity in {"low", "medium", "high", "critical"} else "unknown", {"continue": 0.25, "escalate": 0.75} if high_risk else {"continue": 0.8, "escalate": 0.2}, recommended_escalation=high_risk, observed_event_hash=event.event_hash)


class HttpInferenceProvider:
    def __init__(self, config: InferenceConfig, *, provider_id: str, openai_compatible: bool = False) -> None:
        if not config.endpoint:
            raise ValueError(f"{config.provider} inference requires inferenceEndpoint")
        self.config = config
        self.provider_id = provider_id
        self.openai_compatible = openai_compatible

    def _prompt(self, event: DecisionEnvelope) -> str:
        return (
            f"You are Shield advisory classifier profile {self.config.prompt_profile}. "
            "Return JSON only with risk_category, recommended_escalation, and transition_probabilities. "
            "Do not claim causality. The local policy decision is authoritative.\n"
            + json.dumps(event.body(), sort_keys=True, separators=(",", ":"))
        )

    def analyze(self, event: DecisionEnvelope) -> JevAnalysis:
        prompt = self._prompt(event)
        body: dict[str, Any]
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        api_key = os.environ.get("SHIELD_INFERENCE_API_KEY", "")
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        if self.openai_compatible:
            body = {"model": self.config.model, "messages": [{"role": "user", "content": prompt}], "temperature": self.config.temperature, "max_tokens": self.config.max_tokens, "response_format": {"type": "json_object"}}
        else:
            body = {"model": self.config.model, "prompt": prompt, "max_tokens": self.config.max_tokens, "temperature": self.config.temperature}
        request = Request(self.config.endpoint, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
        try:
            with urlopen(request, timeout=self.config.timeout_ms / 1000) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (OSError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"{self.provider_id} inference failed: {exc}") from exc
        if self.openai_compatible:
            content = payload.get("choices", [{}])[0].get("message", {}).get("content", "")
            payload = json.loads(content) if isinstance(content, str) else content
        probabilities = payload.get("transition_probabilities") or {"continue": 1 - float(payload.get("confidence", 0.5)), "escalate": float(payload.get("confidence", 0.5))}
        return JevAnalysis(self.provider_id, "available", str(payload.get("risk_category") or "unknown"), {str(k): float(v) for k, v in probabilities.items()}, bool(payload.get("recommended_escalation", False)), event.event_hash)


def build_inference_provider(settings: Mapping[str, Any]) -> tuple[InferenceConfig, JevProvider | None]:
    config = InferenceConfig.from_settings(settings)
    if not config.enabled:
        return config, None
    if config.provider == "jev":
        return config, FixtureJevProvider()
    if config.provider == "local_classifier":
        return config, LocalClassifierProvider()
    if config.provider == "lila":
        return config, HttpInferenceProvider(config, provider_id="lila")
    if config.provider == "llm":
        return config, HttpInferenceProvider(config, provider_id=f"llm:{config.model or 'configured'}", openai_compatible=True)
    raise ValueError(f"unknown inference provider {config.provider!r}")


__all__ = ["InferenceConfig", "LocalClassifierProvider", "HttpInferenceProvider", "build_inference_provider"]
