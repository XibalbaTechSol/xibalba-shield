"""Deterministic, explainable risk assessment for normalized Shield events.

This module deliberately does not use an LLM and does not make network calls.  It
turns evidence already present on a canonical event into a bounded assessment that
can be attached to the OPA decision.  OPA remains authoritative; this layer only
hardens an otherwise permissive result when a high-confidence local signal is
present.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Literal

from ..schemas.events import NormalizedEvent


HUMAN_CONFIDENCE_THRESHOLD = 0.75
CONTAIN_CONFIDENCE_THRESHOLD = 0.90


@dataclass(frozen=True)
class RiskSignal:
    name: str
    weight: float
    reason: str


@dataclass(frozen=True)
class RiskAssessment:
    score: float
    confidence: float
    suggested_action: Literal["allow", "log_only", "escalate", "contain"]
    human_required: bool
    signals: tuple[RiskSignal, ...] = ()


def _severity_weight(value: str) -> float:
    return {"low": 0.0, "medium": 0.20, "high": 0.45, "critical": 0.75}.get(value.lower(), 0.15)


def assess_event(event: NormalizedEvent) -> RiskAssessment:
    """Assess only observable evidence; never infer intent from free-form text."""

    signals: list[RiskSignal] = []
    activity = getattr(event, "activity", None)
    severity = str(getattr(activity, "severity", getattr(activity, "risk_level", "low")))
    severity_weight = _severity_weight(severity)
    if severity_weight:
        signals.append(RiskSignal("declared_severity", severity_weight, f"event severity is {severity}"))

    process = getattr(event, "process", None)
    exe_path = str(getattr(process, "exe_path", ""))
    if exe_path and any(fnmatch(exe_path, pattern) for pattern in (
        "/tmp/*", "/var/tmp/*", "/dev/shm/*", "*/ai/*", "*/llm-tools/*", "*/shadow-agent/*"
    )):
        signals.append(RiskSignal("suspicious_execution_path", 0.65, f"executable came from {exe_path}"))

    file_info = getattr(event, "file", None)
    file_path = str(getattr(file_info, "path", ""))
    if file_path and any(fnmatch(file_path, pattern) for pattern in (
        "/home/*/.ssh/*", "/etc/*", "/var/secrets/*"
    )):
        signals.append(RiskSignal("sensitive_resource", 0.55, f"sensitive path accessed: {file_path}"))

    agent = getattr(event, "agent", None)
    agent_activity = getattr(event, "activity", None)
    if agent is not None and bool(getattr(agent_activity, "policy_violation", False)):
        signals.append(RiskSignal("agent_policy_violation", 0.70, "agent activity marked as a policy violation"))

    score = min(1.0, max([0.0, *(signal.weight for signal in signals)]))
    # Confidence is evidence quality, not merely severity.  A single explicit
    # policy violation is high confidence; a severity-only report is weaker.
    confidence = min(1.0, score + (0.20 if len(signals) >= 2 else 0.0))
    if any(signal.name in {"suspicious_execution_path", "agent_policy_violation"} for signal in signals):
        confidence = min(1.0, confidence + 0.10)

    if confidence >= CONTAIN_CONFIDENCE_THRESHOLD:
        suggested_action: Literal["allow", "log_only", "escalate", "contain"] = "contain"
    elif confidence >= HUMAN_CONFIDENCE_THRESHOLD:
        suggested_action = "escalate"
    elif signals:
        suggested_action = "log_only"
    else:
        suggested_action = "allow"
    return RiskAssessment(
        score=round(score, 3),
        confidence=round(confidence, 3),
        suggested_action=suggested_action,
        human_required=confidence < HUMAN_CONFIDENCE_THRESHOLD and bool(signals),
        signals=tuple(signals),
    )
