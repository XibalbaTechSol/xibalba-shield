"""Shield interprets a policy result exactly as the shared decision vectors say (integrity-core B2 stage 4).

`integrity-sdk/tests/conformance/decision_vectors.json` (in integrity-core) is shared with the SDK, which runs it
through `resolve()`, and with `bcc_middleware`, which runs it through its own `PackPolicy.decide_sync`. This file runs
every `scope: result` vector through SHIELD's own path -- `PolicyEngine.evaluate_with_basis`, including how it extracts
the contract result from the evaluator's raw object -- with only the OPA transport stubbed to return the vector's result.

That seam is the point. `resolve()` was always right; Shield's code *around* it was not: it only treated a result as
a decision when it carried both `decision` and `reason_code`, and read any non-object result as "no rule matched",
so `{"decision": "deny"}` or `"deny"` took the event class's default (log_only or permit for sensor events) instead of
failing closed. These vectors are what keep that fixed.

The file is found beside this repo (a local checkout of integrity-core) or inside it (CI checks integrity-core out at a
pinned ref, see .github/workflows/ci.yml). Missing is a failure, never a skip: a skipped conformance test proves nothing.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from integrity_sdk.core.decision import NO_MATCH
from integrity_sdk.core.packs import LoadedPack

from shield.opa_local import load_signed_profile_pack
from shield.policy_engine.engine import EvaluationContext, PolicyEngine
from shield.schemas.events import Activity, ProcessActivity, ProcessInfo

REPO = Path(__file__).resolve().parents[1]
CANDIDATES = [
    REPO.parent / "integrity-core" / "integrity-sdk" / "tests" / "conformance" / "decision_vectors.json",
    REPO / "integrity-core" / "integrity-sdk" / "tests" / "conformance" / "decision_vectors.json",
]


def _load() -> list[dict]:
    for path in CANDIDATES:
        if path.is_file():
            return [v for v in json.loads(path.read_text())["vectors"] if v["scope"] == "result"]
    raise FileNotFoundError(
        "decision_vectors.json not found. Expected a sibling integrity-core checkout or the CI checkout at "
        f"{CANDIDATES}. This is a failure, not a skip: the conformance vectors are not optional."
    )


VECTORS = _load()
EVENT_CLASS = "process_activity"


def _event() -> ProcessActivity:
    # Benign on purpose: the local risk gate may only harden an allow, and nothing here should trip it.
    return ProcessActivity(
        device_id="dev-1", process=ProcessInfo(pid=1, name="calc", exe_path="/usr/bin/calc"), activity=Activity(type="launch"),
    )


def _basis_for(vector):
    pack: LoadedPack = load_signed_profile_pack("smb")
    manifest = {**pack.manifest, "event_classes": {EVENT_CLASS: {"no_match": vector["default"]}}}
    pack = dataclasses.replace(pack, manifest=manifest)
    raw = vector["result"]
    result = NO_MATCH if isinstance(raw, dict) and raw.get("$undefined") is True else raw
    client = Mock()
    client.query.return_value = result
    with patch("shield.policy_engine.engine.OpaClient", return_value=client):
        engine = PolicyEngine(pack=pack)
    _decision, basis = engine.evaluate_with_basis(_event(), EvaluationContext(tenant_id="t", device_id="dev-1"))
    return basis


def test_the_vectors_were_found_and_cover_the_contract():
    assert {v["default"] for v in VECTORS} == {"deny", "log_only", "permit"}
    assert sum(1 for v in VECTORS if v["expect"]["reason_code"] == "INTEGRITY_MALFORMED_DECISION") >= 30


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["name"])
def test_shield_interprets_the_result_as_the_vector_says(vector):
    # A vector may carry ONE documented exception for Shield (its evaluator returns the whole package object, so an
    # object with none of decision/reason_code/controls means "no rule matched"). The exception is explicit and pinned,
    # not skipped: Shield must still produce exactly the outcome it states.
    expect = vector.get("exceptions", {}).get("shield", {}).get("expect", vector["expect"])
    basis = _basis_for(vector)
    blocks = basis.decision == "deny"  # enforce mode: only a deny blocks; contain/escalate record as deny
    assert blocks == expect["blocks"], f"{vector['name']}: Shield recorded {basis.decision!r}, expected blocks={expect['blocks']}"
    assert basis.reason_code == expect["reason_code"]
    assert list(basis.controls) == expect["controls"]


def test_shield_has_exactly_the_two_documented_exceptions():
    """If this count changes, a vector gained or lost a Shield exception: that is a contract-surface change, not a routine edit."""
    assert sorted(v["name"] for v in VECTORS if "shield" in v.get("exceptions", {})) == [
        "empty_object_is_malformed",
        "empty_object_is_malformed_even_if_the_default_permits",
    ]
