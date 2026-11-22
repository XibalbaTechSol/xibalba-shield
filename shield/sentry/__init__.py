"""
Xibalba Shield — Agent Defense Sentry & Proof-of-Justification (PoJ) Subsystem.

Implements three production-grade defense phases for autonomous agents:
- Phase 1: Ingress Taint Tracking, Zero-Width Canary Traps, and Zero-Leak PII/Secret Scrubbers.
- Phase 2: Proof-of-Justification (PoJ) Tool Gating and Execution Ticket Middleware.
- Phase 3: OCSF Class 6003 (AI/ML Activity) SIEM Exporter and AES-256-GCM Tenant Enclaves.
"""

from __future__ import annotations

from .taint import TaintLevel, TaintRecord, TaintLatticeTracker
from .canary import CanaryTrap, CanaryManager
from .scrubber import SecretScrubber, scrub_secrets_and_pii
from .justification import (
    ToolRiskLevel,
    ToolRiskPolicy,
    ExecutionTicket,
    ProofOfJustificationEngine,
    PoJAuthorizationError,
)
from .ocsf import OCSFActivityId, OCSFSeverityId, OCSFEventBuilder
from .enclave import TenantEnclave, EnclaveError
from .store import SentryDefenseStore

__all__ = [
    "TaintLevel",
    "TaintRecord",
    "TaintLatticeTracker",
    "CanaryTrap",
    "CanaryManager",
    "SecretScrubber",
    "scrub_secrets_and_pii",
    "ToolRiskLevel",
    "ToolRiskPolicy",
    "ExecutionTicket",
    "ProofOfJustificationEngine",
    "PoJAuthorizationError",
    "OCSFActivityId",
    "OCSFSeverityId",
    "OCSFEventBuilder",
    "TenantEnclave",
    "EnclaveError",
    "SentryDefenseStore",
]
