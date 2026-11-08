"""Nurse Rachel Wisconsin Medicaid Policy Pack Loader, Deterministic Evaluator,
and Closed-Loop AIS Reward Engine.

Integrates the signed `nurse-rachel-wi-medicaid` policy pack (`packs/nurse-rachel-wi-medicaid/`)
with the canonical `ais/v1-geometric-1` mathematical specification and step/epoch reward
functions (`R_total = R_task + lambda * AIS`).
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple
import yaml


PACK_DIR = Path(__file__).resolve().parents[2] / "packs" / "nurse-rachel-wi-medicaid"

UNAUTHORIZED_MEDICAL_KEYWORDS = (
    "prescribe",
    "prescription",
    "rx",
    "diagnose",
    "diagnosis",
    "titrate",
    "dosage adjustment",
    "stop taking medication",
)


@dataclass(frozen=True)
class PolicyPackManifest:
    """Loaded and hash-verified Nurse Rachel Wisconsin Medicaid policy pack."""

    name: str
    version: str
    pack_format: str
    decision_contract: str
    entrypoint: str
    event_classes: Dict[str, Any]
    controls: Dict[str, List[str]]
    pack_hash: str
    signer_key: str
    signature: str
    rego_source: str


@dataclass(frozen=True)
class PolicyDecisionResult:
    """Deterministic policy pack evaluation result (`integrity.decision/1`)."""

    effect: str  # "PERMIT" | "DENY"
    reason_code: str
    control_id: str
    pack_hash: str
    severity: str
    obligations: Tuple[str, ...]

    @property
    def allowed(self) -> bool:
        return self.effect == "PERMIT"


@dataclass(frozen=True)
class ClinicalAISRewardStep:
    """Step-level AIS (`ais/v1-geometric-1`) and reward calculation for Nurse Rachel."""

    s_entropy: float
    s_grounding: float
    s_contribution: float
    s_compliance: float
    ais_score_1000: float
    ais_normalized: float
    r_task: float
    ais_reward_term: float
    potential_shaping: float
    violation_penalty: float
    r_total: float
    gated_by_compliance: bool


def load_nurse_rachel_policy_pack(pack_dir: Path = PACK_DIR) -> PolicyPackManifest:
    """Load and verify the file digests of the signed `nurse-rachel-wi-medicaid` pack."""
    pack_yaml_bytes = (pack_dir / "pack.yaml").read_bytes().replace(b"\r\n", b"\n")
    controls_yaml_bytes = (pack_dir / "controls.yaml").read_bytes().replace(b"\r\n", b"\n")
    policy_rego_bytes = (pack_dir / "policy.rego").read_bytes().replace(b"\r\n", b"\n")
    sig_json = json.loads((pack_dir / "pack.sig.json").read_text(encoding="utf-8"))

    expected_files = sig_json["signed_manifest"]["files"]
    actual_files = {
        "controls.yaml": "sha256:" + hashlib.sha256(controls_yaml_bytes).hexdigest(),
        "pack.yaml": "sha256:" + hashlib.sha256(pack_yaml_bytes).hexdigest(),
        "policy.rego": "sha256:" + hashlib.sha256(policy_rego_bytes).hexdigest(),
    }
    for fname, expected_digest in expected_files.items():
        if actual_files.get(fname) != expected_digest:
            raise ValueError(
                f"Policy pack digest mismatch on {fname}: expected {expected_digest}, got {actual_files.get(fname)}"
            )

    raw_manifest = yaml.safe_load(pack_yaml_bytes.decode("utf-8"))
    raw_controls = yaml.safe_load(controls_yaml_bytes.decode("utf-8"))

    return PolicyPackManifest(
        name=raw_manifest["name"],
        version=raw_manifest["version"],
        pack_format=raw_manifest["pack_format"],
        decision_contract=raw_manifest["decision_contract"],
        entrypoint=raw_manifest["entrypoint"],
        event_classes=dict(raw_manifest["event_classes"]),
        controls=dict(raw_controls),
        pack_hash=sig_json["pack_hash"],
        signer_key=sig_json["signer_key"],
        signature=sig_json["signature"],
        rego_source=policy_rego_bytes.decode("utf-8"),
    )


class NurseRachelPolicyEvaluator:
    """Deterministic evaluator for `nurse-rachel-wi-medicaid` policy rules."""

    def __init__(self, pack_dir: Path = PACK_DIR) -> None:
        self.manifest = load_nurse_rachel_policy_pack(pack_dir)

    def evaluate(self, policy_input: Mapping[str, Any]) -> PolicyDecisionResult:
        """Evaluate an event payload against the 7 Wisconsin Medicaid & HIPAA rules."""
        reasons: List[Tuple[str, str]] = []

        # 1. HIPAA § 164.502(e) & § 164.312(b): BAA Endpoint Verification
        if policy_input.get("target_endpoint") and not policy_input.get("baa_verified_endpoint", True):
            reasons.append(("NR_HIPAA_NON_BAA_ENDPOINT", "HIPAA-164.312(b)-164.502(e)"))

        # 2. Scope-of-Practice Boundary (Wis. Stat. § 441.06)
        serialized_args = str(policy_input.get("serialized_args", "")).lower()
        for kw in UNAUTHORIZED_MEDICAL_KEYWORDS:
            if kw in serialized_args:
                reasons.append(("NR_CONTAIN_UNAUTHORIZED_MEDICAL_PRACTICE", "WI-NPA-441.06"))
                break

        event_class = str(policy_input.get("event_class", "agent.tool_call"))

        # 3. 21st Century Cures Act § 12006(a): EVV 6 Elements & 250m Geofence
        if event_class == "clinical.evv":
            if not policy_input.get("evv_six_elements_complete", True):
                reasons.append(("NR_CURES_EVV_MISSING_STATUTORY_FIELDS", "US-CURES-12006(a)"))
            gps_distance = float(policy_input.get("gps_distance_meters", 0.0))
            if gps_distance > 250.0 and not policy_input.get("cms_manual_edit_reason_code"):
                reasons.append(("NR_CURES_EVV_GEOFENCE_BREACH", "US-CURES-12006(a)"))

        # 4-7. Wisconsin Medicaid Claim Release & Authorization Rules (`clinical.claim`)
        if event_class == "clinical.claim":
            days_rn = int(policy_input.get("days_since_last_rn_supervisory_visit", 0))
            if days_rn > 60:
                reasons.append(("NR_WI_DHS_105_17_SUPERVISORY_OVERDUE", "WI-DHS-105.17(2)(b)"))

            if bool(policy_input.get("member_inpatient_admitted", False)):
                reasons.append(("NR_WI_DHS_107_112_HOSPITAL_HOLD", "WI-DHS-107.112(4)"))

            req_units = float(policy_input.get("weekly_units_requested", 0.0))
            used_units = float(policy_input.get("weekly_units_used", 0.0))
            auth_units = float(policy_input.get("weekly_units_authorized", float("inf")))
            if (req_units + used_units > auth_units) and not policy_input.get("rn_override_cosigned", False):
                reasons.append(("NR_WI_DHS_107_112_PA_UNIT_CAP_EXCEEDED", "WI-DHS-107.112(1)-(3)"))

            if not policy_input.get("cms_485_physician_signed", True) or not policy_input.get(
                "face_to_face_within_window", True
            ):
                reasons.append(("NR_ACA_6407_UNSIGNED_POC_OR_F2F", "US-ACA-6407-42CFR440.70"))

        if reasons:
            reasons.sort(key=lambda item: item[0])
            code, control_id = reasons[0]
            return PolicyDecisionResult(
                effect="DENY",
                reason_code=code,
                control_id=control_id,
                pack_hash=self.manifest.pack_hash,
                severity="critical",
                obligations=("HALT_EXECUTION", "EMIT_MERKLE_RECEIPT", "NOTIFY_SUPERVISING_RN"),
            )

        return PolicyDecisionResult(
            effect="PERMIT",
            reason_code="NR_COMPLIANT_PERMIT",
            control_id="HIPAA-164.312(b)-164.502(e)",
            pack_hash=self.manifest.pack_hash,
            severity="low",
            obligations=(),
        )


def compute_clinical_ais_and_reward(
    r_task: float,
    entropy_variance: float = 0.05,
    grounding_ratio: float = 1.0,
    graph_contribution: float = 500.0,
    penalty_severity: float = 0.0,
    zk_coverage_ratio: float = 0.5,
    prev_ais_1000: float = 1000.0,
    policy_denied: bool = False,
    lambda_ais: float = 0.50,
    gamma: float = 0.99,
    shaping_weight: float = 0.25,
    deny_penalty: float = 1.0,
) -> ClinicalAISRewardStep:
    """Compute canonical `ais/v1-geometric-1` and closed-loop reward `R_total`."""
    s_e = 0.0 if (math.isnan(entropy_variance) or entropy_variance < 0.0) else 1000.0 * math.exp(-1.5 * (entropy_variance ** 2))
    s_g = 1000.0 * min(max(grounding_ratio, 0.0), 1.0)
    s_s = 0.0 if graph_contribution < 0.0 else 1000.0 * min(math.log10(graph_contribution + 1.0) / 3.0, 1.0)
    s_c = 1000.0 * (1.0 - min(max(penalty_severity, 0.0), 1.0))

    weights = (0.30, 0.25, 0.15, 0.30)
    axes = (s_e, s_g, s_s, s_c)
    if any(w > 0.0 and a <= 0.0 for w, a in zip(weights, axes)):
        ais_base = 0.0
    else:
        ais_base = math.exp(sum(w * math.log(a) for w, a in zip(weights, axes)))

    zk_boost = 1.0 + 0.15 * min(max(zk_coverage_ratio, 0.0), 1.0)
    ais_1000 = min(ais_base * zk_boost, 1000.0)
    ais_norm = ais_1000 / 1000.0

    gated = bool(policy_denied or s_c <= 0.0)
    eff_task = 0.0 if gated else float(r_task)
    ais_term = lambda_ais * ais_norm

    phi_t = ais_norm ** 2
    phi_prev = (min(max(prev_ais_1000, 0.0), 1000.0) / 1000.0) ** 2
    shaping = shaping_weight * (gamma * phi_t - phi_prev)

    penalty = deny_penalty if policy_denied else 0.0
    r_total = eff_task + ais_term + shaping - penalty

    return ClinicalAISRewardStep(
        s_entropy=s_e,
        s_grounding=s_g,
        s_contribution=s_s,
        s_compliance=s_c,
        ais_score_1000=ais_1000,
        ais_normalized=ais_norm,
        r_task=eff_task,
        ais_reward_term=ais_term,
        potential_shaping=shaping,
        violation_penalty=penalty,
        r_total=r_total,
        gated_by_compliance=gated,
    )
