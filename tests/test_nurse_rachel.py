"""Tests for the Nurse Rachel vertical, Shield PreToolUse gate, and AIS feedback loop."""

import pytest
from pathlib import Path
from datetime import datetime, timezone

from shield.nurse_rachel.agent import NurseRachelAgent
from shield.nurse_rachel.governor import ActionSpaceZone, AISGovernor
from shield.nurse_rachel.models import (
    ADLCategory,
    AssistanceLevel,
    TriageUrgency,
)
from shield.nurse_rachel.vault import PatientVault


@pytest.fixture
def temp_vault(tmp_path: Path) -> PatientVault:
    secret = b"unit-test-super-secret-key-32b!"
    return PatientVault(storage_root=tmp_path / "vaults", vault_secret_key=secret)


@pytest.fixture
def agent(temp_vault: PatientVault) -> NurseRachelAgent:
    did = "did:integrity:test_nurse_rachel_did_001"
    return NurseRachelAgent(agent_did=did, vault=temp_vault, initial_ais=1.0)


@pytest.mark.asyncio
async def test_nominal_vitals_logging_green_zone(agent: NurseRachelAgent):
    """Verify nominal vitals logging executes and records cleanly in the Green zone."""
    patient_id = "patient_wi_medicaid_9901"
    token = agent.start_patient_session(patient_id)
    assert token.startswith("SUBJECT_")
    assert agent.governor.current_zone == ActionSpaceZone.GREEN

    tool_args = {
        "patient_token": token,
        "systolic_bp": 128,
        "diastolic_bp": 82,
        "heart_rate_bpm": 74,
        "oxygen_saturation_pct": 98,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }

    result = await agent.handle_tool_proposal("log_vital_signs", tool_args)
    assert result.allowed is True
    assert result.zone == ActionSpaceZone.GREEN
    assert result.receipt_hash is not None
    assert result.output_payload["status"] == "success"

    # Verify stored in isolated vault
    history = agent.vault.get_patient_history(patient_id)
    assert len(history["vitals"]) == 1
    assert history["vitals"][0]["systolic_bp"] == 128


@pytest.mark.asyncio
async def test_clinical_boundary_prescription_denial(agent: NurseRachelAgent):
    """Verify that an attempt to prescribe or adjust medication is deterministically blocked."""
    token = agent.start_patient_session("patient_wi_medicaid_9902")

    tool_args = {
        "patient_token": token,
        "instructions": "Increase your insulin prescription by 5 units.",
    }

    result = await agent.handle_tool_proposal("log_vital_signs", tool_args)
    assert result.allowed is False
    assert "Clinical boundary breach" in result.reason
    assert "cannot diagnose, prescribe" in result.reason
    assert result.current_ais < 1.0  # Penalized in closed loop

    # Verify patient-facing response formatting
    patient_msg = agent.format_patient_response(result)
    assert "cannot provide medical advice" in patient_msg
    assert "call 911" in patient_msg


@pytest.mark.asyncio
async def test_non_baa_endpoint_denial(agent: NurseRachelAgent):
    """Verify that attempting to route data to an untrusted/non-BAA endpoint is rejected."""
    token = agent.start_patient_session("patient_wi_medicaid_9903")

    tool_args = {
        "patient_token": token,
        "category": ADLCategory.BATHING.value,
        "assistance_level": AssistanceLevel.PARTIAL_PHYSICAL.value,
        "duration_minutes": 45,
        "notes": "Assisted with morning bath.",
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }

    result = await agent.handle_tool_proposal(
        "record_adl_observation",
        tool_args,
        target_endpoint="api.untrusted-third-party.io",
    )
    assert result.allowed is False
    assert "Business Associate Agreement (BAA)" in result.reason
    assert result.current_ais <= 0.70  # Severe penalty applied


@pytest.mark.asyncio
async def test_closed_loop_ais_action_space_contraction(agent: NurseRachelAgent):
    """Verify that dropping AIS from Green -> Yellow -> Red dynamically contracts the action space."""
    token = agent.start_patient_session("patient_wi_medicaid_9904")
    assert agent.governor.current_zone == ActionSpaceZone.GREEN

    # 1. Nominal state: log_vital_signs is allowed
    assert agent.governor.is_action_permitted("log_vital_signs") is True

    # 2. Simulate drift or minor penalty dropping AIS to 0.85 (Yellow Zone)
    agent.governor.update_ais(0.85)
    assert agent.governor.current_zone == ActionSpaceZone.YELLOW

    # In Yellow Zone: log_vital_signs (autonomous write) is blocked, but care plan query & draft notes are allowed
    assert agent.governor.is_action_permitted("log_vital_signs") is False
    assert agent.governor.is_action_permitted("query_care_plan") is True
    assert agent.governor.is_action_permitted("dispatch_rn_escalation") is True

    # 3. Simulate severe failure dropping AIS to 0.60 (Red Zone)
    agent.governor.update_ais(0.60)
    assert agent.governor.current_zone == ActionSpaceZone.RED

    # In Red Zone: only emergency escalation is permitted
    assert agent.governor.is_action_permitted("query_care_plan") is False
    assert agent.governor.is_action_permitted("log_vital_signs") is False
    assert agent.governor.is_action_permitted("dispatch_rn_escalation") is True
    assert agent.governor.is_action_permitted("emergency_911_dispatch") is True


def test_patient_vault_isolation(temp_vault: PatientVault):
    """Verify strict tenant isolation between distinct patient records."""
    p1 = "patient_alpha_101"
    p2 = "patient_beta_202"

    t1 = temp_vault.tokenize_patient_id(p1)
    t2 = temp_vault.tokenize_patient_id(p2)
    assert t1 != t2

    temp_vault.record_vitals(p1, {"systolic_bp": 120, "recorded_at": "2026-11-07T12:00:00Z"})
    temp_vault.record_vitals(p2, {"systolic_bp": 145, "recorded_at": "2026-11-07T13:00:00Z"})

    hist1 = temp_vault.get_patient_history(p1)
    hist2 = temp_vault.get_patient_history(p2)

    assert len(hist1["vitals"]) == 1
    assert hist1["vitals"][0]["systolic_bp"] == 120

    assert len(hist2["vitals"]) == 1
    assert hist2["vitals"][0]["systolic_bp"] == 145
