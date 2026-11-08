"""Closed-loop AIS governor for Nurse Rachel.

Implements the dynamic action-space constraint function:
    A(t) = G(AIS_t, BCC)
"""

from enum import Enum
from typing import Dict, List, Set


class ActionSpaceZone(str, Enum):
    GREEN = "green"  # Nominal autonomy: full clinical logging & check-ins
    YELLOW = "yellow"  # Supervised / Degraded: read-only, draft-only, RN co-sign required
    RED = "red"  # Critical halt / Tripped: emergency escalation only, session lock


class AISGovernor:
    """Dynamic Action Space Governor backed by Agent Integrity Score (AIS).

    Enforces deterministic control bounds on the agent's executable actions.
    """

    GREEN_THRESHOLD = 0.90
    YELLOW_THRESHOLD = 0.75

    GLOBAL_TOOL_CATALOG: Set[str] = {
        "log_vital_signs",
        "record_adl_observation",
        "query_care_plan",
        "dispatch_rn_escalation",
        "draft_caregiver_note",
        "emergency_911_dispatch",
    }

    ZONE_PERMISSIONS: Dict[ActionSpaceZone, Set[str]] = {
        ActionSpaceZone.GREEN: {
            "log_vital_signs",
            "record_adl_observation",
            "query_care_plan",
            "dispatch_rn_escalation",
            "draft_caregiver_note",
            "emergency_911_dispatch",
        },
        ActionSpaceZone.YELLOW: {
            "query_care_plan",
            "draft_caregiver_note",
            "dispatch_rn_escalation",
            "emergency_911_dispatch",
        },
        ActionSpaceZone.RED: {
            "dispatch_rn_escalation",
            "emergency_911_dispatch",
        },
    }

    def __init__(self, initial_ais: float = 1.0):
        self._ais = max(0.0, min(1.0, initial_ais))
        self._violations: List[str] = []

    @property
    def current_ais(self) -> float:
        return self._ais

    @property
    def current_zone(self) -> ActionSpaceZone:
        if self._ais >= self.GREEN_THRESHOLD:
            return ActionSpaceZone.GREEN
        elif self._ais >= self.YELLOW_THRESHOLD:
            return ActionSpaceZone.YELLOW
        else:
            return ActionSpaceZone.RED

    def get_allowed_actions(self) -> Set[str]:
        """Compute A(t) = G(AIS_t, BCC)."""
        return self.ZONE_PERMISSIONS[self.current_zone]

    def is_action_permitted(self, action_name: str) -> bool:
        """Check if action is in the currently restricted action space."""
        return action_name in self.get_allowed_actions()

    def update_ais(self, new_ais: float) -> ActionSpaceZone:
        """Receive authoritative AIS update from Integrity Oracle."""
        self._ais = max(0.0, min(1.0, new_ais))
        return self.current_zone

    def penalize_violation(self, reason: str, penalty: float = 0.15) -> ActionSpaceZone:
        """Apply closed-loop penalty on policy or clinical boundary breach."""
        self._violations.append(reason)
        self._ais = max(0.0, self._ais - penalty)
        return self.current_zone

    def reward_verified_compliance(self, delta: float = 0.05) -> ActionSpaceZone:
        """Apply positive feedback when supervised actions are co-signed."""
        self._ais = min(1.0, self._ais + delta)
        return self.current_zone
