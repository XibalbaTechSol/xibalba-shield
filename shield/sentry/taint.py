"""
Phase 1: Ingress Taint Tracking and Security Lattice.

Defines a strict lattice-based information flow security model:
    TRUSTED_AXIOM (1)  <  AGENT_INFERENCE (2)  <  UNTRUSTED_INGEST (3)

Rules:
1. Join operator (⊔): least upper bound in risk order (max risk). If ANY causal input
   is UNTRUSTED_INGEST, derived state inherits UNTRUSTED_INGEST.
2. Meet operator (⊓): greatest lower bound in risk order (min risk).
3. Sensitive/Mutating tools require clearance. An UNTRUSTED_INGEST context cannot
   invoke HIGH or CRITICAL tools without cryptographic decontamination or PoJ verification.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Mapping, Sequence


class TaintLevel(IntEnum):
    """Lattice security levels ordered by risk."""
    TRUSTED_AXIOM = 1     # Verified developer rules, signed policy bundles, hard axioms
    AGENT_INFERENCE = 2   # Autonomous intermediate thoughts, model plans, reasoning
    UNTRUSTED_INGEST = 3  # External web data, user prompts, API payloads, file uploads

    @classmethod
    def from_str(cls, val: str | int) -> TaintLevel:
        if isinstance(val, int) and val in cls._value2member_map_:
            return cls(val)
        val_str = str(val).strip().upper()
        if "AXIOM" in val_str or "TRUSTED" in val_str:
            return cls.TRUSTED_AXIOM
        if "INFERENCE" in val_str or "MODEL" in val_str:
            return cls.AGENT_INFERENCE
        return cls.UNTRUSTED_INGEST

    def join(self, other: TaintLevel) -> TaintLevel:
        """Lattice join (least upper bound): max risk."""
        return TaintLevel(max(self.value, other.value))

    def meet(self, other: TaintLevel) -> TaintLevel:
        """Lattice meet (greatest lower bound): min risk."""
        return TaintLevel(min(self.value, other.value))

    def allows_clearance(self, required_max_risk: TaintLevel) -> bool:
        """Returns True if self's risk does not exceed required_max_risk."""
        return self.value <= required_max_risk.value


@dataclass(frozen=True)
class TaintRecord:
    """Immutable record tracking provenance and taint of data in the agent runtime."""
    record_id: str
    content: str
    taint_level: TaintLevel
    source: str
    source_type: str
    timestamp: str
    provenance_hash: str
    canary_ids: tuple[str, ...] = ()
    decontaminated: bool = False
    decontamination_proof: Mapping[str, Any] | None = None

    @classmethod
    def create(
        cls,
        content: str,
        *,
        taint_level: TaintLevel = TaintLevel.UNTRUSTED_INGEST,
        source: str = "ingress",
        source_type: str = "untrusted_input",
        canary_ids: Sequence[str] = (),
        record_id: str | None = None,
    ) -> TaintRecord:
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return cls(
            record_id=record_id or f"tnt_{uuid.uuid4().hex[:12]}",
            content=content,
            taint_level=taint_level,
            source=source,
            source_type=source_type,
            timestamp=ts,
            provenance_hash=content_hash,
            canary_ids=tuple(canary_ids),
            decontaminated=False,
            decontamination_proof=None,
        )


class TaintLatticeTracker:
    """Tracks and computes taint propagation across causal agent steps."""

    def __init__(self) -> None:
        self._records: dict[str, TaintRecord] = {}

    def track_ingest(
        self,
        content: str,
        *,
        source: str = "user_input",
        source_type: str = "prompt",
        level: TaintLevel = TaintLevel.UNTRUSTED_INGEST,
        canary_ids: Sequence[str] = (),
    ) -> TaintRecord:
        """Registers a new ingress data element and assigns its initial taint level."""
        record = TaintRecord.create(
            content,
            taint_level=level,
            source=source,
            source_type=source_type,
            canary_ids=canary_ids,
        )
        self._records[record.record_id] = record
        return record

    def propagate(
        self,
        inputs: Sequence[TaintRecord | TaintLevel],
        output_content: str,
        *,
        source: str = "agent_derivation",
        source_type: str = "inference_output",
    ) -> TaintRecord:
        """
        Computes the lattice join over all input dependencies.
        If inputs is empty, defaults to AGENT_INFERENCE.
        """
        if not inputs:
            effective_level = TaintLevel.AGENT_INFERENCE
            canary_ids: set[str] = set()
        else:
            effective_level = TaintLevel.TRUSTED_AXIOM
            canary_ids = set()
            for inp in inputs:
                if isinstance(inp, TaintRecord):
                    effective_level = effective_level.join(inp.taint_level)
                    canary_ids.update(inp.canary_ids)
                elif isinstance(inp, TaintLevel):
                    effective_level = effective_level.join(inp)

        record = TaintRecord.create(
            output_content,
            taint_level=effective_level,
            source=source,
            source_type=source_type,
            canary_ids=sorted(canary_ids),
        )
        self._records[record.record_id] = record
        return record

    def decontaminate(
        self,
        record: TaintRecord,
        *,
        verifier_identity: str,
        proof_type: str,
        proof_details: Mapping[str, Any],
        target_level: TaintLevel = TaintLevel.TRUSTED_AXIOM,
    ) -> TaintRecord:
        """
        Cryptographically decontaminates a record, lowering its taint level
        upon verified verification / proof-of-justification.
        """
        proof: dict[str, Any] = {
            "verifier_identity": verifier_identity,
            "proof_type": proof_type,
            "proof_details": dict(proof_details),
            "decontaminated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "original_taint_level": record.taint_level.name,
        }
        decontaminated_record = TaintRecord(
            record_id=record.record_id,
            content=record.content,
            taint_level=target_level,
            source=record.source,
            source_type=record.source_type,
            timestamp=record.timestamp,
            provenance_hash=record.provenance_hash,
            canary_ids=record.canary_ids,
            decontaminated=True,
            decontamination_proof=proof,
        )
        self._records[record.record_id] = decontaminated_record
        return decontaminated_record

    def get_record(self, record_id: str) -> TaintRecord | None:
        return self._records.get(record_id)
