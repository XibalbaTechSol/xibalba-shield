"""Shield's gate-daemon receipts: a thin adapter over the SDK's shared writer (integrity-core B2).

What lives where
----------------
The durable, concurrency-safe, crash-safe receipt writer -- fsync-before-answer, torn-tail handling, rollback,
refusal to continue a log that does not verify, the privacy rules -- is `integrity_sdk.core.receipt_writer`, shared
with `bcc_middleware`. Its module docstring is the authority on failure posture; nothing there is restated here so the
two cannot disagree. The receipt *format* is `integrity_sdk.core.receipts` (SDK contract C4), verified independently
by `integrity-cli`.

This module keeps only what is Shield's own:

* the **action binding**: a Shield receipt's action is the tool name and the tool-input digest (never the input),
  ``f"{tool_name}\\x00{tool_input_sha256 or ''}"`` -- byte for byte what this repository hashed before the writer moved,
  so logs written before the swap keep verifying and continuing;
* the **log id** (``shield-gate:`` + a prefix of the device HMAC), also unchanged;
* the original public names, so `gate_daemon` and `cli` import from here as before.

Rotation is deliberately NOT enabled: Shield runs one flat log per device (the layout it has always had). Epochs
exist in the SDK for gates that need them.

Failure posture: unchanged and inherited -- start-up fails closed on a log that does not verify; recording raises
`ReceiptWriteError` without advancing the chain, and whether the *decision* stands (strict, the default, or
`--lenient-receipts`) is the daemon's policy, not this module's.
"""

from __future__ import annotations

import os  # noqa: F401  (re-exported on purpose: tests patch os.write / os.fsync through this module's namespace)
from typing import Optional, Sequence

from integrity_sdk.core.receipt_writer import (
    CHECKPOINTS_FILENAME,
    DEFAULT_CHECKPOINT_EVERY,
    MIN_HMAC_KEY_BYTES,
    RECEIPTS_FILENAME,
    GateReceiptWriter as _SdkGateReceiptWriter,
    ReceiptRef,
    ReceiptSetupError,
    ReceiptWriteError,
    derive_log_id,
    load_hmac_key,
    load_signer,
)

__all__ = [
    "CHECKPOINTS_FILENAME", "DEFAULT_CHECKPOINT_EVERY", "MIN_HMAC_KEY_BYTES", "RECEIPTS_FILENAME",
    "GateReceiptWriter", "ReceiptRef", "ReceiptSetupError", "ReceiptWriteError",
    "default_log_id", "load_hmac_key", "load_signer",
]


def default_log_id(hmac_key: bytes, device_id: str) -> str:
    """A stable log id for one device that does not contain the device id (see `derive_log_id`)."""
    return derive_log_id("shield-gate", hmac_key, device_id)


class GateReceiptWriter(_SdkGateReceiptWriter):
    """The SDK writer with Shield's tool-call vocabulary."""

    def record(  # type: ignore[override]
        self,
        *,
        agent_did: str,
        device_id: str,
        tool_name: str,
        tool_input_sha256: Optional[str],
        event_class: str,
        pack_hash: str,
        decision: str,
        reason_code: str,
        mode: str,
        controls: Sequence[str] = (),
        timestamp: Optional[str] = None,
    ) -> ReceiptRef:
        """Record one decision, or raise `ReceiptWriteError`. The action binds the tool name AND the input digest, so
        it identifies this exact call to someone holding the HMAC key and the input, and nothing to anyone else."""
        return super().record(
            agent_did=agent_did, device_id=device_id, action=f"{tool_name}\x00{tool_input_sha256 or ''}",
            event_class=event_class, pack_hash=pack_hash, decision=decision, reason_code=reason_code, mode=mode,
            controls=controls, timestamp=timestamp,
        )
