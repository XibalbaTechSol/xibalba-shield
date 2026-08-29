from __future__ import annotations

from unittest.mock import AsyncMock, patch
from uuid import UUID

import pytest
from integrity_sdk.policy.opa_client import OPADecision

from shield.agent_core.eventlog import EventLog
from shield.agent_core.registry import AgentRegistry, DeviceContext
from shield.agent_core.router import EventRouter
from shield.integrity_exporter.exporter import IntegrityExporter
from shield.policy_engine.engine import PolicyEngine
from shield.schemas.events import (
    AgentActivity,
    AgentContext,
    AgentEvent,
    AgentInfo,
    Decision,
    EventRef,
    PolicyDecision,
    RuleRef,
)


@pytest.fixture(autouse=True)
def mock_opa():
    with patch("shield.policy_engine.engine.opa_evaluate", new_callable=AsyncMock) as mock_eval:
        mock_eval.return_value = OPADecision(allow=True, raw_result={"action": "allow"})
        yield mock_eval


def _decision(**kwargs) -> PolicyDecision:
    return PolicyDecision(
        device_id="dev-1",
        event_ref=EventRef(klass="agent_event", event_id="evt-1"),
        rule=RuleRef(rule_id="r1", name="test", version="1"),
        decision=Decision(action="deny"),
        **kwargs,
    )


def _agent_event(invocation_id: str) -> AgentEvent:
    return AgentEvent(
        device_id="dev-1",
        agent=AgentInfo(agent_id="agent-1", name="Agent One"),
        context=AgentContext(tools_called=["shell"]),
        activity=AgentActivity(type="tool_execution"),
        invocation_id=invocation_id,
    )


def _router(*, exporter=None, event_log=None) -> EventRouter:
    return EventRouter(
        device=DeviceContext(device_id="dev-1", tenant_id="tenant-1", device_role="workstation"),
        registry=AgentRegistry(),
        policy_engine=PolicyEngine(),
        exporter=exporter,
        event_log=event_log,
    )


def test_policy_decision_default_invocation_id_is_canonical_uuid4():
    invocation_id = _decision().invocation_id

    parsed = UUID(invocation_id)
    assert parsed.version == 4
    assert str(parsed) == invocation_id


def test_agent_event_invocation_id_is_preserved_by_policy_evaluation(mock_opa):
    invocation_id = "018f3f62-9ca4-7db5-8a7a-6c26c9f9d820"

    decision = _router().handle(_agent_event(invocation_id))

    assert decision.invocation_id == invocation_id
    assert decision.to_dict()["invocation_id"] == invocation_id


def test_exporter_passes_invocation_id_when_sdk_supports_it(monkeypatch):
    captured = {}

    def build_bcc_commitment(
        *, agent_id, intent_type, intent_payload, nonce, keypair,
        chain_id, verifying_contract, invocation_id,
    ):
        captured.update(
            agent_id=agent_id,
            intent_type=intent_type,
            intent_payload=intent_payload,
            nonce=nonce,
            keypair=keypair,
            chain_id=chain_id,
            verifying_contract=verifying_contract,
            invocation_id=invocation_id,
        )
        return {
            "agent_id": agent_id,
            "nonce": nonce,
            "intended_state_hash": "0x" + "a" * 64,
            "invocation_id": invocation_id,
        }

    monkeypatch.setattr("shield.integrity_exporter.exporter.bcc.build_bcc_commitment", build_bcc_commitment)
    monkeypatch.setattr(
        "shield.integrity_exporter.exporter.bcc.submit_commitment",
        lambda commitment, url: {"authorized": True},
    )

    exporter = IntegrityExporter.__new__(IntegrityExporter)
    exporter.agent_id = "did:integrity:test"
    exporter.keypair = object()
    exporter.bcc_middleware_url = "http://bcc.test"
    exporter.chain_id = 84532
    exporter.verifying_contract = "0x" + "1" * 40
    exporter._nonce_store = type("NonceStore", (), {"next": lambda self: 7})()
    invocation_id = "018f3f62-9ca4-7db5-8a7a-6c26c9f9d820"

    result = exporter.export_decision(_decision(invocation_id=invocation_id))

    assert captured["invocation_id"] == invocation_id
    assert captured["intent_payload"]["invocation_id"] == invocation_id
    assert result["invocation_id"] == invocation_id


def test_invocation_id_is_retained_locally_when_integrity_export_fails(tmp_path, mock_opa):
    class RaisingExporter:
        def export_event(self, event):
            raise RuntimeError("middleware unavailable")

        def export_decision(self, decision):
            raise RuntimeError("middleware unavailable")

    log = EventLog(tmp_path / "decisions.jsonl")
    invocation_id = "018f3f62-9ca4-7db5-8a7a-6c26c9f9d820"

    decision = _router(exporter=RaisingExporter(), event_log=log).handle(_agent_event(invocation_id))
    retained = log.recent(1)[0]

    assert decision.invocation_id == invocation_id
    assert decision.export.invocation_id == invocation_id
    assert decision.export.decision_exported is False
    assert retained["invocation_id"] == invocation_id
    assert retained["export"]["invocation_id"] == invocation_id


def test_exporter_rejects_mismatched_bcc_response_invocation_id(monkeypatch):
    invocation_id = "018f3f62-9ca4-7db5-8a7a-6c26c9f9d820"

    def build_commitment(
        *, agent_id, intent_type, intent_payload, nonce, keypair,
        chain_id, verifying_contract, invocation_id,
    ):
        return {
            "agent_id": agent_id,
            "nonce": nonce,
            "intended_state_hash": "0x" + "a" * 64,
            "invocation_id": invocation_id,
        }

    monkeypatch.setattr(
        "shield.integrity_exporter.exporter.bcc.build_bcc_commitment",
        build_commitment,
    )
    monkeypatch.setattr(
        "shield.integrity_exporter.exporter.bcc.submit_commitment",
        lambda commitment, url: {
            "authorized": True,
            "invocation_id": "dbe846dc-a57f-4a8d-aa9d-b36d9dd62279",
        },
    )

    exporter = IntegrityExporter.__new__(IntegrityExporter)
    exporter.agent_id = "did:integrity:test"
    exporter.keypair = object()
    exporter.bcc_middleware_url = "http://bcc.test"
    exporter.chain_id = 84532
    exporter.verifying_contract = "0x" + "1" * 40
    exporter._nonce_store = type("NonceStore", (), {"next": lambda self: 8})()

    result = exporter.export_decision(_decision(invocation_id=invocation_id))

    assert result["authorized"] is False
    assert "does not match" in result["reason"]
    assert result["invocation_id"] == invocation_id
