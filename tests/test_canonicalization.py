from __future__ import annotations

from shield.canonical import CANONICALIZATION, canonical_bytes


def test_shield_artifact_canonicalization_uses_sdk_jcs():
    assert CANONICALIZATION == "xibalba.canonical-json.v2"
    assert canonical_bytes({"z": 1, "text": "café"}) == '{"text":"café","z":1}'.encode("utf-8")
