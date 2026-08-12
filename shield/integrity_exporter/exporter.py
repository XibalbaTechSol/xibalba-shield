"""
Integrity Telemetry & AIS-Feeding Exporter — spec/xibalba-shield-v1.md §4.5.

Turns local decisions into signed evidence using Integrity Protocol's EXISTING primitives, with
no privileged shortcut: DID assignment via `integrity_sdk.did`, BCC commitment signing via
`integrity_sdk.bcc`, submission to `bcc_middleware` exactly the way `pretool_gate.py`
(`integrity-core`'s own Xibalba session hooks) already does it for Claude Code tool calls —
this module generalizes that same pattern into a reusable library rather than reinventing it.

Two distinct export paths, matching the two kinds of thing Shield produces (spec §4.5):
  - `export_decision`: a PolicyDecision IS a gating decision about whether something was
    allowed to happen — maps to `POST /v1/bcc/intercept`, the parent repo's pre-execution gate,
    via a real signed BCC commitment whose `intent_type` is one of §5.6's security-event types.
  - `export_event`: raw sensor observations (ProcessActivity/FileActivity/NetworkFlow/
    AgentEvent) carry no gating decision of their own — they become evidence via the existing
    `IntegrityClient.log_telemetry`/`flush_telemetry` path (`POST /v1/telemetry/ingest`), the
    same telemetry pipeline every other integrity-sdk integration already uses.

AIS deltas are NEVER computed here — `integrity-oracle`'s scoring-core is the only place that
turns evidence into a score (protocol spec §8.1's "sole computer" rule), and this module has no
code path that bypasses that.

Restored 2026-08-12 after a 2026-08-07 refactor deleted this module in favor of OTel-only
telemetry with no signed-commitment path (see xibalba-shield/IMPLEMENTATION_PLAN.md's former
"Known gap — 2026-08-12"). One deliberate change from the original: `IntegrityClient` is
constructed with `background_flush=True` (the SDK's own default) instead of the original
`background_flush=False`. Shield's decisions fire on a real-time enforcement path — a `contain`/
`deny` decision must not block on a synchronous telemetry flush to a possibly slow or unreachable
`bcc_middleware`. `export_decision`'s own BCC submission is a separate, single-shot call (not
routed through the batched telemetry client) and remains best-effort/logged-not-raised as before.
"""

from __future__ import annotations

import logging
from typing import Any

from integrity_sdk import bcc, did as sdk_did
from integrity_sdk.client import IntegrityClient

from ..schemas.events import INTENT_TYPES, NormalizedEvent, PolicyDecision

logger = logging.getLogger("shield.integrity_exporter")

# Maps a PolicyDecision's rule/action shape onto the closest §5.6 intent_type. Deliberately a
# small, explicit table rather than a generic passthrough — an unbounded free-text intent_type
# would defeat the point of having a pinned vocabulary in the first place (see
# docs/INTERFACE_CONTRACT.md's own reasoning for pinning the BCC intent_type shape).
_ACTION_TO_INTENT_TYPE = {
    "contain": "agent_contained",
    "deny": "connection_blocked",
    "escalate": "guardrail_denied",
}


def _intent_type_for(decision: PolicyDecision) -> str:
    if decision.event_ref.klass == "agent_event" and decision.decision.action in ("deny", "escalate"):
        return "guardrail_denied"
    return _ACTION_TO_INTENT_TYPE.get(decision.decision.action, "device_posture_change")


class IntegrityExporter:
    def __init__(
        self,
        *,
        bcc_middleware_url: str,
        oracle_url: str | None = None,
        agent_label: str = "xibalba-shield",
    ) -> None:
        # Bootstraps (or reuses) a real local DID/keypair the same way pretool_gate.py's
        # load_bridged_identity does — one identity per device/deployment, persisted under
        # integrity-sdk's own agent_dir convention so restarts don't mint a new DID each time.
        self.agent_id, self.keypair, self.doc = sdk_did.load_or_create_did(agent_label)
        self.bcc_middleware_url = bcc_middleware_url.rstrip("/")
        self._nonce_store = bcc.NonceStore(sdk_did.agent_dir(agent_label) / "bcc_nonce")
        self._telemetry_client = IntegrityClient(
            self.agent_id,
            oracle_url,
            keypair=self.keypair,
            auto_flush=True,
            background_flush=True,
        )

    def export_decision(self, decision: PolicyDecision) -> dict[str, Any]:
        intent_type = _intent_type_for(decision)
        assert intent_type in INTENT_TYPES, f"unmapped intent_type {intent_type!r}"

        commitment = bcc.build_bcc_commitment(
            agent_id=self.agent_id,
            intent_type=intent_type,
            intent_payload=decision.to_dict(),
            nonce=self._nonce_store.next(),
            keypair=self.keypair,
        )
        try:
            return bcc.submit_commitment(commitment, self.bcc_middleware_url)
        except Exception as exc:  # noqa: BLE001
            # Evidence export is best-effort by design (spec §4.5 doesn't require it to
            # block enforcement) — a real decision was already made and acted on upstream;
            # losing the evidence submission must not be silently invisible, so it's logged
            # loudly rather than swallowed.
            logger.warning("BCC submission failed for decision %s: %r", decision.event_ref.event_id, exc)
            return {"authorized": False, "reason": f"submission failed: {exc}"}

    def export_event(self, event: NormalizedEvent) -> None:
        self._telemetry_client.log_telemetry({"shield_event": event.to_dict()})

    def flush(self) -> None:
        self._telemetry_client.flush_telemetry()
