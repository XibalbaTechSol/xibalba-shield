"""Off-chain first-run registration of the Shield exporter's DID with the Oracle.

`register_offchain` (integrity-sdk, registration_offchain.py) is mocked: this covers the
exporter's stamp/skip/failure bookkeeping, not the Oracle wire protocol.
"""

from __future__ import annotations

import json
import sys
import types
from unittest.mock import MagicMock, patch

import pytest

ORACLE = "https://oracle.example"
DID = "did:integrity:abc123"


class _FakeOffchainError(RuntimeError):
    def __init__(self, status, detail):
        super().__init__(detail)
        self.status = status
        self.detail = detail


@pytest.fixture
def sdk_module(monkeypatch):
    mod = types.ModuleType("integrity_sdk.registration_offchain")
    mod.OffchainRegistrationError = _FakeOffchainError
    mod.register_offchain = MagicMock(
        return_value=types.SimpleNamespace(agent_id="a-1", verification_tier=1, outcome="created", handle=None)
    )
    monkeypatch.setitem(sys.modules, "integrity_sdk.registration_offchain", mod)
    return mod


def _make(tmp_path, monkeypatch, oracle_url=ORACLE, label="xibalba-shield-reg-test"):
    monkeypatch.setenv("INTEGRITY_DID_HOME", str(tmp_path / "did"))
    from shield.integrity_exporter import IntegrityExporter

    with patch("shield.integrity_exporter.exporter.IntegrityClient") as client, patch(
        "shield.integrity_exporter.exporter.sdk_did.load_or_create_did"
    ) as load, patch("shield.integrity_exporter.exporter.bcc") as bcc:
        load.return_value = (DID, object(), {"id": DID})
        bcc.NonceStore.return_value = MagicMock()
        client.return_value = MagicMock(_batcher=None)
        return IntegrityExporter(
            bcc_middleware_url="http://unused", oracle_url=oracle_url, agent_label=label,
            spool_db_path=tmp_path / "spool.db",
        )


def _stamp(tmp_path, label="xibalba-shield-reg-test"):
    return tmp_path / "did" / label / "oracle_registered.json"


def test_first_run_registers_and_stamps(tmp_path, monkeypatch, sdk_module):
    exp = _make(tmp_path, monkeypatch)
    result = exp.register_offchain_once()
    assert result == {"status": "registered", "tier": 1, "outcome": "created"}
    sdk_module.register_offchain.assert_called_once()
    assert sdk_module.register_offchain.call_args.args[:2] == (ORACLE, DID)
    stamp = json.loads(_stamp(tmp_path).read_text())
    assert (stamp["did"], stamp["oracle_url"], stamp["tier"]) == (DID, ORACLE, 1)
    assert stamp["at"]
    assert not list(_stamp(tmp_path).parent.glob("*.tmp*"))


def test_second_run_with_stamp_does_not_call_oracle(tmp_path, monkeypatch, sdk_module):
    _make(tmp_path, monkeypatch).register_offchain_once()
    sdk_module.register_offchain.reset_mock()
    assert _make(tmp_path, monkeypatch).register_offchain_once() == {"status": "skipped"}
    sdk_module.register_offchain.assert_not_called()


def test_first_run_survives_unreachable_oracle(tmp_path, monkeypatch, sdk_module, caplog):
    sdk_module.register_offchain.side_effect = _FakeOffchainError(None, "connection refused")
    with caplog.at_level("WARNING"):
        result = _make(tmp_path, monkeypatch).register_offchain_once()
    assert result == {"status": "failed", "http_status": None, "detail": "connection refused"}
    assert not _stamp(tmp_path).exists()  # retried on next start
    assert any(r.levelname == "WARNING" for r in caplog.records)


def test_stamp_for_a_different_oracle_url_reregisters(tmp_path, monkeypatch, sdk_module):
    _make(tmp_path, monkeypatch, oracle_url="https://old.example").register_offchain_once()
    sdk_module.register_offchain.reset_mock()
    result = _make(tmp_path, monkeypatch).register_offchain_once()
    assert result["status"] == "registered"
    sdk_module.register_offchain.assert_called_once()
    assert json.loads(_stamp(tmp_path).read_text())["oracle_url"] == ORACLE


def test_no_oracle_url_is_skipped(tmp_path, monkeypatch, sdk_module):
    assert _make(tmp_path, monkeypatch, oracle_url=None).register_offchain_once() == {"status": "skipped"}
    sdk_module.register_offchain.assert_not_called()


def test_sdk_without_registration_offchain_fails_without_raising(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "integrity_sdk.registration_offchain", None)  # ImportError
    result = _make(tmp_path, monkeypatch).register_offchain_once()
    assert result == {
        "status": "failed", "http_status": None,
        "detail": "integrity-sdk lacks registration_offchain; upgrade",
    }


def test_unexpected_error_never_raises(tmp_path, monkeypatch, sdk_module):
    sdk_module.register_offchain.side_effect = ValueError("did does not match")
    result = _make(tmp_path, monkeypatch).register_offchain_once()
    assert result["status"] == "failed"
