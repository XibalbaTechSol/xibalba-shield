from unittest.mock import patch

from shield.config import DeviceConfig
from shield.config.tls import build_client_context
from shield.runtime_status import publish_runtime_status


class _Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None


def test_runtime_status_skips_unconfigured_backend():
    config = DeviceConfig(device_id="dev-1")
    assert publish_runtime_status(device_config=config, policy_status={}, opa_status={}) is False


@patch("shield.runtime_status.urlopen", return_value=_Response())
def test_runtime_status_falls_back_to_device_token_without_a_key(mock_urlopen, tmp_path, monkeypatch):
    """A device enrolled before the assertion migration has no signing key and must keep working."""
    monkeypatch.setenv("INTEGRITY_DID_HOME", str(tmp_path))
    config = DeviceConfig(
        device_id="dev-1", tenant_id="tenant-1", device_token="secret", backend_url="http://backend"
    )

    assert publish_runtime_status(
        device_config=config,
        policy_status={"healthy": True},
        opa_status={"healthy": True},
    ) is True
    request = mock_urlopen.call_args.args[0]
    assert request.full_url == "http://backend/api/shield/exporter-status"
    assert request.get_header("Authorization") == "Bearer secret"


@patch("shield.runtime_status.urlopen", return_value=_Response())
def test_runtime_status_signs_an_assertion_when_a_key_is_present(mock_urlopen, tmp_path, monkeypatch):
    """With a device key on disk, the long-lived token must not be sent at all."""
    from integrity_sdk.did import Keypair

    from shield.device_assertion import ASSERTION_SCHEME, verify_assertion
    from integrity_sdk.did import fingerprint_for_pubkey

    monkeypatch.setenv("INTEGRITY_DID_HOME", str(tmp_path))
    keypair = Keypair.generate()
    key_dir = tmp_path / "xibalba-shield"
    key_dir.mkdir(parents=True)
    (key_dir / "private_key.pem").write_bytes(keypair.private_pem())

    config = DeviceConfig(
        device_id="dev-1", tenant_id="tenant-1", device_token="secret", backend_url="http://backend"
    )
    assert publish_runtime_status(device_config=config, policy_status={}, opa_status={}) is True

    header = mock_urlopen.call_args.args[0].get_header("Authorization")
    assert header.startswith(f"{ASSERTION_SCHEME} ")
    assert "secret" not in header
    enrolled = f"did:integrity:{fingerprint_for_pubkey(keypair.public_bytes())}"
    assert verify_assertion(
        header,
        expected_audience="http://backend",
        lookup_enrolled_agent_id=lambda *_: enrolled,
    ) is not None


@patch("shield.runtime_status.urlopen", return_value=_Response())
def test_runtime_status_includes_sensors_and_exporter_when_given(mock_urlopen):
    import json

    config = DeviceConfig(
        device_id="dev-1", tenant_id="tenant-1", device_token="secret", backend_url="http://backend"
    )

    assert publish_runtime_status(
        device_config=config,
        policy_status={"healthy": True},
        opa_status={"healthy": True},
        sensors_status={"attached": True, "lost_events": 3, "last_event_at": "2026-09-04T00:00:00Z"},
        exporter_status_detail={"export_failures": 1, "queue_depth": 5},
    ) is True
    request = mock_urlopen.call_args.args[0]
    body = json.loads(request.data)
    assert body["status"]["sensors"] == {"attached": True, "lost_events": 3, "last_event_at": "2026-09-04T00:00:00Z"}
    assert body["status"]["exporter"] == {"export_failures": 1, "queue_depth": 5}


@patch("shield.runtime_status.urlopen", return_value=_Response())
def test_runtime_status_includes_did_preflight_when_given(mock_urlopen):
    import json

    config = DeviceConfig(
        device_id="dev-1", tenant_id="tenant-1", device_token="secret", backend_url="http://backend"
    )
    preflight = {"did": "did:test:agent", "did_loaded": True, "bcc_middleware_reachable": True}

    assert publish_runtime_status(
        device_config=config,
        policy_status={"healthy": True},
        opa_status={"healthy": True},
        did_preflight_detail=preflight,
    ) is True
    body = json.loads(mock_urlopen.call_args.args[0].data)
    assert body["status"]["did_preflight"] == preflight


@patch("shield.runtime_status.urlopen", return_value=_Response())
def test_runtime_status_omits_sensors_and_exporter_when_not_given(mock_urlopen):
    import json

    config = DeviceConfig(
        device_id="dev-1", tenant_id="tenant-1", device_token="secret", backend_url="http://backend"
    )

    publish_runtime_status(device_config=config, policy_status={}, opa_status={})
    request = mock_urlopen.call_args.args[0]
    body = json.loads(request.data)
    assert "sensors" not in body["status"]
    assert "exporter" not in body["status"]


@patch("shield.runtime_status.urlopen", return_value=_Response())
def test_runtime_status_includes_responder_gate(mock_urlopen):
    import json

    config = DeviceConfig(device_id="dev-1", tenant_id="tenant-1", device_token="secret", backend_url="http://backend")
    gate = {"capabilities": {"freeze_process": True, "kill_process": False}, "readiness": {"ready": {"kill_process": False}}}
    assert publish_runtime_status(device_config=config, policy_status={}, opa_status={}, responder_status=gate) is True
    body = json.loads(mock_urlopen.call_args.args[0].data)
    assert body["status"]["responders"] == gate


def test_client_tls_settings_require_https_and_complete_key_pair():
    assert build_client_context(DeviceConfig(device_id="dev-1", backend_url="http://backend")) is None
    config = DeviceConfig(device_id="dev-1", backend_url="http://backend", backend_client_cert="client.crt")
    try:
        build_client_context(config)
    except ValueError as exc:
        assert "requires both backend_client_cert" in str(exc)
    else:
        raise AssertionError("partial client credentials must fail closed")
