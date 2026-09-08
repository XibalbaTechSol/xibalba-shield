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
telemetry with no signed-commitment path (see
xibalba-shield/docs/archive/2026-08/IMPLEMENTATION_PLAN.md's former
"Known gap — 2026-08-12"). One deliberate change from the original: `IntegrityClient` is
constructed with `background_flush=True` (the SDK's own default) instead of the original
`background_flush=False`. Shield's decisions fire on a real-time enforcement path — a `contain`/
`deny` decision must not block on a synchronous telemetry flush to a possibly slow or unreachable
`bcc_middleware`. `export_decision`'s own BCC submission is a separate, single-shot call (not
routed through the batched telemetry client) and remains best-effort/logged-not-raised as before.
"""

from __future__ import annotations

import inspect
import logging
import queue
import threading
from typing import Any

from pathlib import Path

from integrity_sdk import bcc, did as sdk_did
from integrity_sdk.client import IntegrityClient

from . import spool
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
        chain_id: int = 84532,
        verifying_contract: str = "0x72e21e44AdD6d6e7CAa02eaedF078630afC40819",
        spool_db_path: Path | str | None = None,
        async_export: bool = False,
        async_queue_size: int = 1024,
    ) -> None:
        # Bootstraps (or reuses) a real local DID/keypair the same way pretool_gate.py's
        # load_bridged_identity does — one identity per device/deployment, persisted under
        # integrity-sdk's own agent_dir convention so restarts don't mint a new DID each time.
        self.agent_id, self.keypair, self.doc = sdk_did.load_or_create_did(agent_label)
        self.bcc_middleware_url = bcc_middleware_url.rstrip("/")
        # integrity-core docs/plans/2026-08-18-phase1-canonical-intent-encoding-proposal.md:
        # every BCC commitment now binds chain_id + verifying_contract (the target chain's
        # XibalbaAgentRegistry). Defaults match Base Sepolia (integrity-core CLAUDE.md's
        # "Live deployment"); a device pointed at a different deployment must configure both
        # via DeviceConfig, same as bcc_middleware_url/oracle_url.
        self.chain_id = chain_id
        self.verifying_contract = verifying_contract
        self._nonce_store = bcc.NonceStore(sdk_did.agent_dir(agent_label) / "bcc_nonce")
        # Colocated with the nonce store under integrity-sdk's own agent_dir convention,
        # not a new DeviceConfig field -- this is an internal durability detail, not
        # something an operator needs to configure per deployment. Overridable for tests.
        self._spool_db_path = Path(spool_db_path) if spool_db_path is not None else sdk_did.agent_dir(agent_label) / "export_spool.db"
        self._telemetry_client = IntegrityClient(
            self.agent_id,
            oracle_url,
            keypair=self.keypair,
            auto_flush=True,
            background_flush=True,
        )
        self._export_failures = 0
        self._async_export = bool(async_export)
        self._decision_queue: queue.Queue[dict[str, Any]] | None = None
        self._decision_queue_dropped = 0
        if getattr(self, "_async_export", False):
            if async_queue_size < 1:
                raise ValueError("async_queue_size must be positive")
            self._decision_queue = queue.Queue(maxsize=async_queue_size)
            threading.Thread(
                target=self._decision_export_loop,
                name="shield-decision-exporter",
                daemon=True,
            ).start()

    def export_decision(self, decision: PolicyDecision) -> dict[str, Any]:
        intent_type = _intent_type_for(decision)
        assert intent_type in INTENT_TYPES, f"unmapped intent_type {intent_type!r}"

        commitment_kwargs = {
            "agent_id": self.agent_id,
            "intent_type": intent_type,
            "intent_payload": decision.to_dict(),
            "nonce": self._nonce_store.next(),
            "keypair": self.keypair,
        }
        commitment_params = inspect.signature(bcc.build_bcc_commitment).parameters
        if "chain_id" in commitment_params:
            commitment_kwargs["chain_id"] = self.chain_id
        if "verifying_contract" in commitment_params:
            commitment_kwargs["verifying_contract"] = self.verifying_contract
        if "invocation_id" in commitment_params:
            # The pinned SDK remains backward compatible during the cross-repository rollout.
            # Once its pin includes invocation-id v1 this value is signed into the commitment.
            commitment_kwargs["invocation_id"] = decision.invocation_id

        commitment = bcc.build_bcc_commitment(**commitment_kwargs)
        if getattr(self, "_async_export", False):
            assert self._decision_queue is not None
            try:
                self._decision_queue.put_nowait(commitment)
            except queue.Full:
                self._decision_queue_dropped += 1
                spool.enqueue(
                    self._spool_db_path,
                    kind="decision",
                    payload=commitment,
                    error="asynchronous decision export queue is full",
                )
                return {
                    "authorized": False,
                    "queued": False,
                    "reason": "decision export queue full; commitment spooled",
                    "invocation_id": decision.invocation_id,
                    "invocation_id_signed": "invocation_id" in commitment,
                }
            return {
                "authorized": False,
                "queued": True,
                "reason": "decision queued for asynchronous export",
                "invocation_id": decision.invocation_id,
                "invocation_id_signed": "invocation_id" in commitment,
            }
        return self._submit_commitment(commitment, decision.invocation_id, decision.event_ref.event_id)

    def _submit_commitment(self, commitment: dict[str, Any], invocation_id: str, event_id: str) -> dict[str, Any]:
        try:
            result = bcc.submit_commitment(commitment, self.bcc_middleware_url)
            if isinstance(result, dict):
                returned_invocation_id = result.get("invocation_id")
                if returned_invocation_id not in (None, invocation_id):
                    raise RuntimeError(
                        "BCC response invocation_id does not match the signed commitment"
                    )
                result.setdefault("agent_id", commitment["agent_id"])
                result.setdefault("nonce", commitment["nonce"])
                result.setdefault("intended_state_hash", commitment["intended_state_hash"])
                result.setdefault("invocation_id", invocation_id)
                result.setdefault("invocation_id_signed", "invocation_id" in commitment)
            return result
        except Exception as exc:  # noqa: BLE001
            # Evidence export is best-effort by design (spec §4.5 doesn't require it to
            # block enforcement) — a real decision was already made and acted on upstream;
            # losing the evidence submission must not be silently invisible, so it's logged
            # loudly rather than swallowed.
            logger.warning("BCC submission failed for decision %s: %r", event_id, exc)
            self._export_failures += 1
            # Spool the already-built, already-signed commitment for later replay --
            # see spool.py's module docstring for why this is safe to resend as-is
            # (no new nonce, no re-signing) and what "delivered" means on replay.
            spool.enqueue(self._spool_db_path, kind="decision", payload=commitment, error=str(exc))
            return {
                "authorized": False,
                "reason": f"submission failed: {exc}",
                "invocation_id": invocation_id,
                "invocation_id_signed": False,
            }

    def _decision_export_loop(self) -> None:
        assert self._decision_queue is not None
        while True:
            commitment = self._decision_queue.get()
            try:
                # build_bcc_commitment emits a flat wire object. The decision
                # payload is hashed into intended_state_hash; it is not retained
                # under an intent_payload key. Reading that nonexistent nested
                # object passed an empty ID to the correlation check and turned
                # valid async responses into false mismatch retries.
                invocation_id = str(commitment.get("invocation_id", ""))
                self._submit_commitment(commitment, invocation_id, "")
            except Exception:  # pragma: no cover - defensive worker boundary
                logger.exception("asynchronous decision export worker failed")
            finally:
                self._decision_queue.task_done()

    def replay_pending(self) -> spool.RetryCycleResult:
        """One retry pass over the durable spool -- called periodically by
        `shield.watchdog.Watchdog.tick()`, independent of new decisions arriving.
        Never raises: an unreachable `bcc_middleware` just leaves rows pending for
        the next tick, same as a single spooled row's own retry failure."""
        return spool.run_retry_cycle(
            self._spool_db_path,
            lambda payload: bcc.submit_commitment(payload, self.bcc_middleware_url),
        )

    def export_event(self, event: NormalizedEvent) -> None:
        self._telemetry_client.log_telemetry({"shield_event": event.to_dict()})

    def flush(self) -> None:
        self._telemetry_client.flush_telemetry()

    def health(self) -> dict:
        """Watchdog telemetry for the exporter. `queue_depth` reaches into the SDK's
        private `TelemetryBatcher` because `integrity-sdk` has no public API for this yet
        (see integrity-core/docs/PRODUCTION_READINESS_PLAN.md §5, "Backbone contract" --
        SDK API stability is owed to downstream consumers, not yet delivered). If the
        private shape ever changes, this reads `None`, not raises.

        Deliberately does NOT call `batcher.drain_dropped_count()`: that read is
        consuming (resets the SDK's counter, "since the last call" by design) and the
        SDK's own `flush_telemetry` already relies on being its one and only caller to
        report drops as a real oracle metric (`integrity.telemetry.dropped_entries`).
        A second caller here would silently steal/undercount that signal instead of
        adding a new one -- a dropped-entry count would need a real SDK API (a
        non-consuming peek) to be surfaced safely, not this workaround."""
        batcher = getattr(self._telemetry_client, "_batcher", None)
        queue_depth = None
        if batcher is not None:
            try:
                queue_depth = batcher.queue_depth()
            except AttributeError:
                queue_depth = None
        spool_status = spool.status(self._spool_db_path)
        result = {
            "export_failures": self._export_failures,
            "queue_depth": queue_depth,
            "spool_pending": spool_status["pending"],
            "spool_oldest_age_seconds": spool_status["oldest_age_seconds"],
        }
        if self._async_export:
            result.update({
                "decision_queue_depth": self._decision_queue.qsize() if self._decision_queue is not None else 0,
                "decision_queue_dropped": self._decision_queue_dropped,
            })
        return result
