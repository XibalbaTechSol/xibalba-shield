"""Hermes-facing network telemetry consumer with an analysis-only boundary."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .hermes_transport import HermesSpool

_ALLOWED_ADVISORY_KEYS = frozenset({"classification", "confidence", "evidence_refs", "recommendation", "uncertainty"})
_FORBIDDEN_KEYS = frozenset({"command", "shell", "firewall_command", "router_command", "execute", "credentials", "raw_payload"})


class HermesNetworkConsumer:
    """Consume authenticated redacted events and return bounded advisory analysis."""

    def __init__(self, spool: HermesSpool, analyzer: Callable[[Mapping[str, Any]], Mapping[str, Any]]) -> None:
        self.spool = spool
        self.analyzer = analyzer

    @staticmethod
    def _validate_advisory(advisory: Mapping[str, Any]) -> dict[str, Any]:
        keys = set(advisory)
        if keys & _FORBIDDEN_KEYS or not keys.issubset(_ALLOWED_ADVISORY_KEYS):
            raise ValueError("Hermes network analysis contains forbidden control or unknown fields")
        confidence = float(advisory.get("confidence", 0.0) or 0.0)
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("Hermes advisory confidence must be between 0 and 1")
        return {
            "classification": str(advisory.get("classification", "unknown"))[:128],
            "confidence": confidence,
            "evidence_refs": [str(value)[:256] for value in list(advisory.get("evidence_refs", []))[:32]],
            "recommendation": str(advisory.get("recommendation", "observe"))[:128],
            "uncertainty": str(advisory.get("uncertainty", ""))[:512],
        }

    def consume_once(self, *, limit: int | None = None) -> tuple[dict[str, int], list[dict[str, Any]]]:
        advisories: list[dict[str, Any]] = []

        def handle(payload: dict[str, Any]) -> None:
            advisories.append(self._validate_advisory(self.analyzer(payload)))

        result = self.spool.consume_network_once(handle, limit=limit)
        return result, advisories


__all__ = ["HermesNetworkConsumer"]
