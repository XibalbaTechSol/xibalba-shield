"""S1 (integrity-core v2 graph deletion): the exporter DID readback reads the v3 `AgentRegistry`.

The v2 `XibalbaAgentRegistry` is deleted in core slice D5, so a deployments file without it must
still read back the registration. The artifact's `status` is what `pilot_gate_report.py` grades.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_oracle_registration.py"
DID = "did:integrity:" + "ab" * 32
REGISTRY = "0x" + "11" * 20
ACTOR = "0x" + "22" * 20
ZERO = "0x" + "00" * 20


def _load():
    spec = importlib.util.spec_from_file_location("verify_oracle_registration", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Registry:
    """Fake `AgentRegistry`: resolveDID returns the v3 AgentRecord tuple."""

    def __init__(self, record):
        self.record = record
        self.seen = []
        outer = self

        class _Fns:
            def resolveDID(self, did):  # noqa: N802 -- contract method name
                outer.seen.append(did)
                return types.SimpleNamespace(call=lambda: outer.record)

        self.functions = _Fns()


def _record(*, pubkey=b"\x01" * 32, actor=ACTOR, registered_at=100, retired_at=0):
    return (pubkey, "0x" + "33" * 20, actor, b"\x00" * 32, "", registered_at, retired_at, 1)


@pytest.fixture
def run(monkeypatch, tmp_path, capsys):
    """Runs main() against a deployments file with only the v3 singletons and a fake registry."""

    def _run(deployments: dict, record):
        mod = _load()
        path = tmp_path / "deployments.json"
        path.write_text(json.dumps(deployments))
        monkeypatch.setenv("DEPLOYMENTS_FILE", str(path))
        monkeypatch.setattr(mod, "_rpc_reachable", lambda url: True)

        fake_chain = types.SimpleNamespace(
            get_w3=lambda url: types.SimpleNamespace(is_connected=lambda: True),
            load_deployments=lambda p: json.loads(Path(p).read_text()),
        )
        fake_did = types.SimpleNamespace(load_or_create_did=lambda label: (DID, None, None))
        fake_sdk = types.SimpleNamespace(chain=fake_chain, did=fake_did)
        monkeypatch.setitem(sys.modules, "integrity_sdk", fake_sdk)
        monkeypatch.setitem(sys.modules, "integrity_sdk.chain", fake_chain)
        monkeypatch.setitem(sys.modules, "integrity_sdk.did", fake_did)

        registry = _Registry(record)
        calls = []
        monkeypatch.setattr(mod, "registry_contract", lambda w3, address: (calls.append(address), registry)[1], raising=False)
        rc = mod.main()
        out = capsys.readouterr()
        return rc, out, calls, registry

    return _run


def test_reads_agent_registry_without_the_v2_registry(run):
    rc, out, calls, registry = run({"singletons": {"AgentRegistry": REGISTRY}}, _record())
    assert rc == 0, out.err
    assert calls == [REGISTRY]
    assert registry.seen == [DID]
    artifact = json.loads(out.out)
    assert artifact["status"] == "pass", artifact
    assert artifact["did"] == DID
    assert artifact["registration"]["actor"] == ACTOR
    assert artifact["registration"]["registered_at"] == 100


def test_ignores_a_v2_registry_entry(run):
    """Both present (today's Base Sepolia file): the v3 registry is the one read."""
    rc, out, calls, _ = run(
        {"singletons": {"AgentRegistry": REGISTRY, "XibalbaAgentRegistry": "0x" + "99" * 20}}, _record()
    )
    assert rc == 0, out.err
    assert calls == [REGISTRY]


def test_missing_agent_registry_is_a_clear_failure(run):
    rc, out, calls, _ = run({"singletons": {"XibalbaAgentRegistry": "0x" + "99" * 20}}, _record())
    assert rc == 1
    assert calls == []
    assert "AgentRegistry" in out.err and "KeyError" not in out.err


def test_no_onchain_record_exits_nonzero(run):
    rc, out, _, _ = run({"singletons": {"AgentRegistry": REGISTRY}}, _record(pubkey=b"\x00" * 32, actor=ZERO, registered_at=0))
    assert rc == 1
    assert "no on-chain AgentRegistry record" in out.err


def test_retired_record_is_not_a_pass(run):
    rc, out, _, _ = run({"singletons": {"AgentRegistry": REGISTRY}}, _record(retired_at=200))
    assert rc == 1
    assert "retired" in out.err
