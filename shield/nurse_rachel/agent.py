"""Nurse Rachel Agent: Complete on-device agent coordinating patient session and triage."""

from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import hashlib
import json

from shield.nurse_rachel.governor import AISGovernor, ActionSpaceZone
from shield.nurse_rachel.vault import PatientVault
from shield.nurse_rachel.executor import GatedActionBroker, GateEvaluationResult


class NurseRachelAgent:
    """Nurse Rachel clinical agent instance for client device deployment."""

    def __init__(
        self,
        agent_did: str,
        vault: PatientVault,
        initial_ais: float = 1.0,
        trusted_baa_endpoints: Optional[set] = None,
    ):
        self.agent_did = agent_did
        self.vault = vault
        self.governor = AISGovernor(initial_ais=initial_ais)
        self.broker = GatedActionBroker(
            governor=self.governor,
            vault=self.vault,
            agent_did=self.agent_did,
            trusted_baa_endpoints=trusted_baa_endpoints,
        )
        self.active_patient_id: Optional[str] = None
        self.active_patient_token: Optional[str] = None

    def start_patient_session(self, patient_id: str) -> str:
        """Bind agent to an active patient session and return de-identified token."""
        self.active_patient_id = patient_id
        self.active_patient_token = self.vault.tokenize_patient_id(patient_id)
        return self.active_patient_token

    def end_patient_session(self):
        """Zero out active in-memory patient context."""
        self.active_patient_id = None
        self.active_patient_token = None

    def get_clinical_prompt_context(self) -> Dict[str, Any]:
        """Produce de-identified, minimum-necessary prompt context (HIPAA §164.502)."""
        if not self.active_patient_id or not self.active_patient_token:
            raise RuntimeError("No active patient session bound.")

        history = self.vault.get_patient_history(self.active_patient_id)
        return {
            "agent_did": self.agent_did,
            "patient_token": self.active_patient_token,
            "current_ais": self.governor.current_ais,
            "action_space_zone": self.governor.current_zone.value,
            "allowed_tools": list(self.governor.get_allowed_actions()),
            "recent_vitals": history["vitals"][:3],
            "recent_adls": history["adls"][:3],
            "instructions": (
                "You are Nurse Rachel, an AI Home Care Assistant for a licensed Personal Care Agency. "
                "You assist with routine ADL tracking, care plan verification, and triage logging. "
                "CLINICAL INVARIANTS: You cannot diagnose conditions or prescribe medications. "
                "Any acute or abnormal condition must be escalated to the supervising RN."
            ),
        }

    async def handle_tool_proposal(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        target_endpoint: str = "local.edge.shield",
    ) -> GateEvaluationResult:
        """Process a model's proposed tool invocation through the Shield PreToolUse gate."""
        if not self.active_patient_token:
            raise RuntimeError("Cannot execute tool without an active patient session.")

        result = await self.broker.evaluate_and_execute(
            action_name=tool_name,
            arguments=tool_args,
            patient_token=self.active_patient_token,
            target_endpoint=target_endpoint,
        )
        return result

    def format_patient_response(self, evaluation: GateEvaluationResult) -> str:
        """Render patient-facing dialogue conditioned on the active closed-loop zone."""
        if not evaluation.allowed:
            if "Clinical boundary breach" in evaluation.reason:
                return (
                    "I cannot provide medical advice, prescribe medications, or adjust dosages. "
                    "I am alerting your supervising Registered Nurse right now. If you are experiencing "
                    "a medical emergency, please call 911 immediately."
                )
            return (
                "This action is restricted by safety policy. The supervising RN has been notified."
            )

        if evaluation.zone == ActionSpaceZone.GREEN:
            return "Thank you. I have recorded that information into your personal care record."

        elif evaluation.zone == ActionSpaceZone.YELLOW:
            return (
                "I have drafted these notes for review by your supervising Registered Nurse. "
                "A clinician will follow up with you shortly."
            )

        elif evaluation.zone == ActionSpaceZone.RED:
            return (
                "The system is currently in restricted emergency mode. Please contact your supervising RN."
            )

        return "Action completed."
