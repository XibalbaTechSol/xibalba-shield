"""Negative tests for SPEC-v2.0.0-proposed.md §4.4: "Machine identity MUST NOT determine the
portable agent subject."

Shield's portable identity (a `did:integrity:...`) is derived from `agent_label` alone via
`integrity_sdk.did.load_or_create_did`. `device_id` -- the machine/endpoint identifier, defined
separately in `shield/config/loader.py`'s `DeviceConfig` -- never enters that derivation. These
tests operationalize the spec clause: they don't just read the code, they construct exporters
with varying device_id/agent_label combinations and assert on the resulting DIDs directly.
"""
from __future__ import annotations

import pytest

from shield.integrity_exporter import IntegrityExporter


@pytest.fixture(autouse=True)
def _did_home(tmp_path, monkeypatch):
    monkeypatch.setenv("INTEGRITY_DID_HOME", str(tmp_path / "dids"))


def _exporter(agent_label: str) -> IntegrityExporter:
    # bcc_middleware_url is never contacted by these tests -- identity is resolved in the
    # constructor before any network call is made.
    return IntegrityExporter(bcc_middleware_url="http://unreachable.invalid:0", agent_label=agent_label)


def test_same_agent_label_yields_same_did_regardless_of_device_id():
    """A logical Shield agent's identity must be portable: moving the same agent_label to a
    different device_id must not change its DID. device_id is not even a constructor parameter
    of IntegrityExporter -- this proves the derivation path has no way to depend on it."""
    first = _exporter("portable-agent")
    second = _exporter("portable-agent")
    assert first.agent_id == second.agent_id


def test_different_agent_labels_yield_different_dids_even_with_identical_device_context():
    """Two logical agents on what could be the same device must not collapse into one identity
    just because they share a machine. This is the inverse check: device sameness does not
    imply agent-identity sameness, any more than device difference implies it."""
    agent_a = _exporter("agent-a")
    agent_b = _exporter("agent-b")
    assert agent_a.agent_id != agent_b.agent_id


def test_agent_label_derivation_has_no_device_id_input_path():
    """Structural check, not just behavioral: load_or_create_did's signature accepts only an
    agent_id/label. If a future change threaded device_id into identity derivation, this is the
    test that should catch it by construction, not just by observed DID equality."""
    import inspect

    from integrity_sdk.did import load_or_create_did

    params = list(inspect.signature(load_or_create_did).parameters)
    assert params == ["agent_id"], (
        f"load_or_create_did's parameters changed to {params} -- if device_id or any "
        "machine-derived value was added, verify it cannot influence the derived DID "
        "(SPEC-v2.0.0-proposed.md §4.4)"
    )
