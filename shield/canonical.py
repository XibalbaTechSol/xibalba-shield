"""Shield's versioned canonical bytes for hashed and signed protocol artifacts."""

from __future__ import annotations

from typing import Any

from integrity_sdk.core.jcs import canonical_bytes as _sdk_canonical_bytes

CANONICALIZATION = "xibalba.canonical-json.v2"


def canonical_bytes(value: Any) -> bytes:
    """Return SDK JCS bytes for Shield artifacts whose bytes are hashed or signed."""
    return _sdk_canonical_bytes(value)


__all__ = ["CANONICALIZATION", "canonical_bytes"]
