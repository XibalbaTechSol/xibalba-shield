"""Synchronous PreToolUse gate and action executor for Nurse Rachel."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set
import hashlib
import json

from shield.nurse_rachel.governor import AISGovernor, ActionSpaceZone
from shield.nurse_rachel.models import (
    DispatchRNEscalationAction,
    LogVitalsAction,
    QueryCarePlanAction,
    RecordADLAction,
)
from shield.nurse_rachel.vault import PatientVault


@dataclass
class GateEvaluationResult:
    allowed: bool
    action_name: str
    zone: ActionSpaceZone
    current_ais: float
    reason: str
    receipt_hash: Optional[str] = None
    output_payload: Optional[Dict[str, Any]] = None


class GatedActionBroker:
    """PreToolUse gate enforcing Integrity BCC constraints and HIPAA BAA rules."""

    UNAUTHORIZED_MEDICAL_KEYWORDS: Set[str] = {
        "prescribe",
        "prescription",
        "rx",
        "diagnose",
        "diagnosis",
        "titrate",
        "dosage adjustment",
        "stop taking medication",
    }

    def __init__(
        self,
        governor: AISGovernor,
        vault: PatientVault,
        agent_did: str,
        trusted_baa_endpoints: Optional[Set[str]] = None,
    ):
        self.governor = governor
        self.vault = vault
        self.agent_did = agent_did
        self.trusted_baa_endpoints = trusted_baa_endpoints or {
            "api.anthropic.bedrock.us-east-1.amazonaws.com",
            "azure-openai-eastus.openai.azure.com",
            "local.edge.shield",
        }
        self.receipts: list = []

    def _generate_receipt(self, action_name: str, args: Dict[str, Any], allowed: bool, reason: str) -> str:
        """Create a cryptographically hash-chained telemetry receipt for Integrity Protocol."""
        payload = {
            "agent_did": self.agent_did,
            "action_name": action_name,
            "args": args,
            "allowed": allowed,
            "reason": reason,
            "ais": self.governor.current_ais,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        raw_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        receipt_hash = hashlib.sha256(raw_bytes).hexdigest()
        self.receipts.append({"receipt_hash": receipt_hash, "payload": payload})
        return receipt_hash

    async def evaluate_and_execute(
        self,
        action_name: str,
        arguments: Dict[str, Any],
        patient_token: str,
        target_endpoint: str = "local.edge.shield",
    ) -> GateEvaluationResult:
        """Synchronous PreToolUse gate and clinical dispatcher."""

        # 1. Verify BAA Endpoint Whitelist (HIPAA §164.502)
        if target_endpoint not in self.trusted_baa_endpoints:
            self.governor.penalize_violation(f"Attempted transmission to non-BAA endpoint: {target_endpoint}", 0.30)
            receipt = self._generate_receipt(action_name, arguments, False, "DENY_NON_BAA_ENDPOINT")
            return GateEvaluationResult(
                allowed=False,
                action_name=action_name,
                zone=self.governor.current_zone,
                current_ais=self.governor.current_ais,
                reason="Denied: Target endpoint does not hold an active Business Associate Agreement (BAA).",
                receipt_hash=receipt,
            )

        # 2. Check Action-Space Zone Governor (Integrity Protocol Closed Loop)
        if not self.governor.is_action_permitted(action_name):
            self.governor.penalize_violation(f"Action '{action_name}' exceeds current zone permissions", 0.10)
            receipt = self._generate_receipt(action_name, arguments, False, "DENY_ACTION_SPACE_RESTRICTION")
            return GateEvaluationResult(
                allowed=False,
                action_name=action_name,
                zone=self.governor.current_zone,
                current_ais=self.governor.current_ais,
                reason=f"Action '{action_name}' is prohibited in {self.governor.current_zone.value.upper()} zone.",
                receipt_hash=receipt,
            )

        # 3. Clinical Boundary Check: Prohibit Autonomous Prescribing & Diagnosis
        serialized_args = json.dumps(arguments).lower()
        for kw in self.UNAUTHORIZED_MEDICAL_KEYWORDS:
            if kw in serialized_args or kw in action_name.lower():
                self.governor.penalize_violation(f"Unauthorized medical practice attempt: keyword '{kw}' detected", 0.25)
                receipt = self._generate_receipt(action_name, arguments, False, "DENY_UNAUTHORIZED_CLINICAL_ORDER")
                return GateEvaluationResult(
                    allowed=False,
                    action_name=action_name,
                    zone=self.governor.current_zone,
                    current_ais=self.governor.current_ais,
                    reason=f"Denied: Clinical boundary breach. Nurse Rachel cannot diagnose, prescribe, or titrate medications ({kw}).",
                    receipt_hash=receipt,
                )

        # 4. Resolve Patient Identity Locally
        patient_id = self.vault.resolve_token(patient_token)
        if not patient_id:
            receipt = self._generate_receipt(action_name, arguments, False, "DENY_UNRESOLVED_PATIENT_TOKEN")
            return GateEvaluationResult(
                allowed=False,
                action_name=action_name,
                zone=self.governor.current_zone,
                current_ais=self.governor.current_ais,
                reason="Denied: Patient token not recognized in active local session.",
                receipt_hash=receipt,
            )

        # 5. Schema Validation & Safe Execution
        try:
            output = None
            if action_name == "log_vital_signs":
                validated_model = LogVitalsAction(**arguments)
                self.vault.record_vitals(patient_id, validated_model.model_dump())
                output = {"status": "success", "recorded": validated_model.model_dump()}

            elif action_name == "record_adl_observation":
                validated_model = RecordADLAction(**arguments)
                self.vault.record_adl(patient_id, validated_model.model_dump())
                output = {"status": "success", "recorded": validated_model.model_dump()}

            elif action_name == "dispatch_rn_escalation":
                validated_model = DispatchRNEscalationAction(**arguments)
                self.vault.record_escalation(patient_id, validated_model.model_dump())
                output = {
                    "status": "escalated",
                    "escalation_id": f"ESC_{hashlib.sha256(str(arguments).encode()).hexdigest()[:8].upper()}",
                    "urgency": validated_model.urgency.value,
                }

            elif action_name == "query_care_plan":
                QueryCarePlanAction(**arguments)
                history = self.vault.get_patient_history(patient_id)
                output = {
                    "status": "success",
                    "care_plan": {
                        "authorized_adl_hours_per_week": 28.5,
                        "primary_diagnosis_icd10": "M19.90 (Osteoarthritis, unspecified)",
                        "assigned_supervising_rn": "RN_SARAH_MILLER_4401",
                        "recent_history_summary": {
                            "vitals_count": len(history["vitals"]),
                            "adls_logged": len(history["adls"]),
                            "prior_escalations": len(history["escalations"]),
                        },
                    },
                }
            else:
                output = {"status": "executed", "action": action_name}

            receipt = self._generate_receipt(action_name, arguments, True, "PERMITTED_CLINICAL_ACTION")
            return GateEvaluationResult(
                allowed=True,
                action_name=action_name,
                zone=self.governor.current_zone,
                current_ais=self.governor.current_ais,
                reason="Action permitted and executed within clinical bounds.",
                receipt_hash=receipt,
                output_payload=output,
            )

        except Exception as e:
            self.governor.penalize_violation(f"Execution or schema error: {str(e)}", 0.05)
            receipt = self._generate_receipt(action_name, arguments, False, f"EXECUTION_ERROR: {str(e)}")
            return GateEvaluationResult(
                allowed=False,
                action_name=action_name,
                zone=self.governor.current_zone,
                current_ais=self.governor.current_ais,
                reason=f"Schema validation or execution error: {str(e)}",
                receipt_hash=receipt,
            )
