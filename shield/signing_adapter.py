"""Isolated client contract for external wallet signing.

Shield never receives or stores private keys. This adapter forwards a previously consumed,
hash-bound approval and an unsigned transaction to a separately operated signer.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.request import Request, urlopen


class SigningAdapterError(RuntimeError):
    """Raised when the external signer rejects or cannot process a request."""


@dataclass(frozen=True)
class SignedTransaction:
    raw_transaction: str
    transaction_hash: str | None = None


class ExternalWalletSigner:
    """Call an isolated signer service; this class has no key-management capability."""

    def __init__(self, endpoint: str, *, timeout: float = 5.0):
        if not endpoint.startswith("https://") and not endpoint.startswith("http://127.0.0.1"):
            raise ValueError("signer endpoint must use HTTPS, except for local test servers")
        self.endpoint = endpoint
        self.timeout = timeout

    def sign(self, *, consumed_approval: dict[str, Any], unsigned_transaction: dict[str, Any]) -> SignedTransaction:
        approval_id = consumed_approval.get("approval_id")
        intent_hash = consumed_approval.get("intent_hash")
        if not approval_id or not intent_hash or not consumed_approval.get("consumed_at"):
            raise SigningAdapterError("signing requires a consumed approval")
        body = {
            "approval_id": approval_id,
            "intent_hash": intent_hash,
            "intent": consumed_approval.get("intent"),
            "unsigned_transaction": unsigned_transaction,
        }
        request = Request(
            self.endpoint,
            data=json.dumps(body, sort_keys=True).encode("utf-8"),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except Exception as exc:  # boundary: normalize transport/parser errors for callers
            raise SigningAdapterError(f"external signer request failed: {exc}") from exc
        raw = payload.get("raw_transaction")
        if not isinstance(raw, str) or not raw.startswith("0x"):
            raise SigningAdapterError("external signer returned no raw transaction")
        tx_hash = payload.get("transaction_hash")
        return SignedTransaction(raw_transaction=raw, transaction_hash=tx_hash if isinstance(tx_hash, str) else None)


__all__ = ["ExternalWalletSigner", "SignedTransaction", "SigningAdapterError"]
