from unittest.mock import AsyncMock, patch

from integrity_sdk.policy.opa_client import OPADecision

from shield.policy_engine.engine import EvaluationContext, PolicyEngine
from shield.policy_engine.risk import assess_event
from shield.schemas.events import Activity, FileActivity, FileInfo, ProcessActivity, ProcessInfo


def _process(path: str, severity: str = "low"):
    return ProcessActivity(
        device_id="dev-1",
        process=ProcessInfo(pid=1, name="worker", exe_path=path),
        activity=Activity(type="launch", severity=severity),
    )


def test_benign_signed_style_path_has_no_risk_signals():
    assessment = assess_event(_process("/usr/bin/python"))
    assert assessment.suggested_action == "allow"
    assert assessment.confidence == 0.0
    assert assessment.human_required is False


def test_suspicious_path_is_high_confidence_containment_evidence():
    assessment = assess_event(_process("/tmp/dropper", "high"))
    assert assessment.suggested_action == "contain"
    assert assessment.confidence >= 0.90
    assert any(signal.name == "suspicious_execution_path" for signal in assessment.signals)


def test_sensitive_file_reaches_review_action_without_high_confidence_containment():
    event = FileActivity(
        device_id="dev-1",
        process=ProcessInfo(pid=1, name="editor", exe_path="/usr/bin/editor"),
        file=FileInfo(path="/home/user/.ssh/id_ed25519", name="id_ed25519"),
        activity=Activity(type="read", severity="medium"),
    )
    assessment = assess_event(event)
    assert assessment.suggested_action == "escalate"
    assert assessment.confidence >= 0.75
    assert assessment.human_required is False


def test_engine_hardens_permissive_opa_result_for_suspicious_execution():
    with patch("shield.policy_engine.engine.opa_evaluate", new_callable=AsyncMock) as evaluate:
        evaluate.return_value = OPADecision(allow=True, raw_result={"action": "allow"})
        decision = PolicyEngine().evaluate(_process("/tmp/dropper", "high"), EvaluationContext(device_id="dev-1"))
    assert decision.decision.action == "contain"
    assert decision.rule.rule_id == "_local-risk-containment"
    assert decision.decision.confidence >= 0.90
    assert decision.decision.evidence
