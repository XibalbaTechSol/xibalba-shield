"""
Phase 1: Zero-Width Cryptographic Canary Trap Defense.

Generates invisible cryptographic tokens using zero-width Unicode characters
and embeds them into untrusted prompt context or system instructions.
If an outgoing response, model thought, or tool parameter leaks the canary trap,
an immediate CANARY_TRIP security alert is triggered.

Zero-width encoding:
  \\u200b -> 00 (ZERO WIDTH SPACE)
  \\u200c -> 01 (ZERO WIDTH NON-JOINER)
  \\u200d -> 10 (ZERO WIDTH JOINER)
  \\ufeff -> 11 (ZERO WIDTH NO-BREAK SPACE)
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

ZW_MAP = {
    0: "\u200b",
    1: "\u200c",
    2: "\u200d",
    3: "\ufeff",
}

REV_ZW_MAP = {
    "\u200b": 0,
    "\u200c": 1,
    "\u200d": 2,
    "\ufeff": 3,
}

ZW_CHARS = set(REV_ZW_MAP.keys())
CANARY_PREFIX = "\u2060\u200b\u200c\ufeff\u200d"
CANARY_SUFFIX = "\u200d\ufeff\u200c\u200b\u2060"


def encode_bytes_to_zw(data: bytes) -> str:
    """Encode bytes into zero-width characters (2 bits per char)."""
    chars = []
    for byte in data:
        for shift in (6, 4, 2, 0):
            val = (byte >> shift) & 0x03
            chars.append(ZW_MAP[val])
    return "".join(chars)


def decode_zw_to_bytes(zw_str: str) -> bytes:
    """Decode zero-width string back to bytes."""
    bits = [REV_ZW_MAP[c] for c in zw_str if c in REV_ZW_MAP]
    # Group in 4 pairs of 2 bits (8 bits = 1 byte)
    out = bytearray()
    for i in range(0, len(bits) - 3, 4):
        byte = (bits[i] << 6) | (bits[i + 1] << 4) | (bits[i + 2] << 2) | bits[i + 3]
        out.append(byte)
    return bytes(out)


@dataclass(frozen=True)
class CanaryTrap:
    canary_id: str
    tenant_id: str
    agent_id: str
    secret_key: str
    created_at: str
    tripped: bool = False
    tripped_at: str | None = None
    tripped_context: str | None = None


@dataclass(frozen=True)
class CanaryTripAlert:
    canary_id: str
    tenant_id: str
    agent_id: str
    detection_time: str
    snippet: str
    severity: str = "critical"


class CanaryManager:
    """Manages creation, injection, and detection of zero-width canary traps."""

    def __init__(self, default_secret: str | bytes = "") -> None:
        self._default_secret = (
            default_secret.encode("utf-8") if isinstance(default_secret, str) else default_secret
        ) or secrets.token_bytes(32)
        self._traps: dict[str, CanaryTrap] = {}

    def _derive_key(self, key: str | bytes | None) -> bytes:
        if not key:
            return self._default_secret
        return key.encode("utf-8") if isinstance(key, str) else key

    def generate_canary(
        self,
        tenant_id: str,
        agent_id: str,
        *,
        secret_key: str | bytes | None = None,
        canary_id: str | None = None,
    ) -> tuple[CanaryTrap, str]:
        """
        Creates a new canary trap and returns the CanaryTrap dataclass and
        its invisible zero-width representation.
        """
        cid = canary_id or f"cny_{uuid.uuid4().hex[:12]}"
        key = self._derive_key(secret_key)
        created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Payload: 8 bytes HMAC tag + 12 bytes canary_id ascii
        id_bytes = cid.encode("ascii")
        tag = hmac.new(key, b"canary:" + id_bytes, hashlib.sha256).digest()[:8]
        raw_payload = tag + id_bytes

        encoded_zw = CANARY_PREFIX + encode_bytes_to_zw(raw_payload) + CANARY_SUFFIX

        trap = CanaryTrap(
            canary_id=cid,
            tenant_id=tenant_id,
            agent_id=agent_id,
            secret_key=key.hex(),
            created_at=created_at,
        )
        self._traps[cid] = trap
        return trap, encoded_zw

    def inject_canary(
        self,
        text: str,
        invisible_canary: str,
        *,
        position: str = "end",
    ) -> str:
        """Injects an invisible canary token into text without modifying visible content."""
        if position == "start":
            return invisible_canary + text
        if position == "middle" and len(text) > 10:
            mid = len(text) // 2
            return text[:mid] + invisible_canary + text[mid:]
        return text + invisible_canary

    def detect_canaries(
        self,
        text: str,
        *,
        secret_key: str | bytes | None = None,
    ) -> list[CanaryTripAlert]:
        """
        Scans text for zero-width canaries and verifies their HMAC signatures.
        Returns list of valid tripped canary alerts.
        """
        if not text:
            return []

        alerts: list[CanaryTripAlert] = []
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Scan for canary delimiters
        idx = 0
        while True:
            start_pos = text.find(CANARY_PREFIX, idx)
            if start_pos == -1:
                break
            end_pos = text.find(CANARY_SUFFIX, start_pos + len(CANARY_PREFIX))
            if end_pos == -1:
                break

            zw_body = text[start_pos + len(CANARY_PREFIX) : end_pos]
            idx = end_pos + len(CANARY_SUFFIX)

            try:
                raw = decode_zw_to_bytes(zw_body)
                if len(raw) < 9:
                    continue
                tag = raw[:8]
                cid_bytes = raw[8:]
                cid = cid_bytes.decode("ascii", errors="ignore")

                # Lookup trap or verify with given key
                trap = self._traps.get(cid)
                key = bytes.fromhex(trap.secret_key) if trap else self._derive_key(secret_key)

                expected_tag = hmac.new(key, b"canary:" + cid_bytes, hashlib.sha256).digest()[:8]
                if hmac.compare_digest(tag, expected_tag):
                    # Valid canary signature detected!
                    tenant_id = trap.tenant_id if trap else "unknown"
                    agent_id = trap.agent_id if trap else "unknown"

                    if trap and not trap.tripped:
                        self._traps[cid] = CanaryTrap(
                            canary_id=trap.canary_id,
                            tenant_id=trap.tenant_id,
                            agent_id=trap.agent_id,
                            secret_key=trap.secret_key,
                            created_at=trap.created_at,
                            tripped=True,
                            tripped_at=now,
                            tripped_context=text[:200],
                        )

                    alerts.append(
                        CanaryTripAlert(
                            canary_id=cid,
                            tenant_id=tenant_id,
                            agent_id=agent_id,
                            detection_time=now,
                            snippet=text[:100],
                            severity="critical",
                        )
                    )
            except Exception:
                continue

        return alerts

    def get_trap(self, canary_id: str) -> CanaryTrap | None:
        return self._traps.get(canary_id)

    def strip_canaries(self, text: str) -> str:
        """Strips zero-width canary tokens and delimiters from text."""
        if not text:
            return ""
        out = text
        while True:
            start_pos = out.find(CANARY_PREFIX)
            if start_pos == -1:
                break
            end_pos = out.find(CANARY_SUFFIX, start_pos + len(CANARY_PREFIX))
            if end_pos == -1:
                break
            out = out[:start_pos] + out[end_pos + len(CANARY_SUFFIX) :]
        return out
