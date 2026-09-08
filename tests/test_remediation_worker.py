from types import SimpleNamespace
from unittest.mock import Mock, patch

from shield.config import DeviceConfig
from shield.remediation_worker import RemediationWorker


def _config():
    return DeviceConfig(device_id="dev-1", tenant_id="tenant-a", device_token="secret", backend_url="http://backend")


@patch.object(RemediationWorker, "_request")
def test_worker_claims_executes_and_completes_retry(request):
    request.side_effect = [
        {"request": {"id": 7, "action": "retry"}},
        {"request": {"id": 7, "status": "completed"}},
    ]
    exporter = Mock(replay_pending=Mock(return_value=SimpleNamespace(attempted=2, delivered=2, failed=0)))
    result = RemediationWorker(device_config=_config(), exporter=exporter).run_once()
    assert result.status == "completed"
    exporter.replay_pending.assert_called_once_with()
    assert request.call_args_list[1].args[:2] == ("POST", "/api/shield/exporter-remediation/complete")
    assert request.call_args_list[1].args[2]["detail"] == {"attempted": 2, "delivered": 2, "failed": 0}


@patch.object(RemediationWorker, "_request", return_value={"request": None})
def test_worker_noops_when_queue_is_empty(request):
    exporter = Mock()
    assert RemediationWorker(device_config=_config(), exporter=exporter).run_once().claimed is False
    exporter.assert_not_called()


@patch.object(RemediationWorker, "_request")
def test_worker_records_terminal_failure(request):
    request.side_effect = [{"request": {"id": 9, "action": "flush"}}, {}]
    exporter = Mock()
    exporter.flush.side_effect = RuntimeError("offline")
    result = RemediationWorker(device_config=_config(), exporter=exporter).run_once()
    assert result.status == "failed"
    assert request.call_args_list[1].args[2]["status"] == "failed"
    assert request.call_args_list[1].args[2]["detail"] == {"error": "offline"}


@patch("shield.remediation_worker.json.load", return_value={"request": None})
@patch("shield.remediation_worker.urlopen")
@patch("shield.remediation_worker.build_client_context")
def test_worker_uses_configured_mtls_context(build_context, urlopen, _json_load):
    config = DeviceConfig(
        device_id="dev-1",
        tenant_id="tenant-a",
        device_token="secret",
        backend_url="https://backend:8443",
        backend_ca_file="/etc/shield/ca.crt",
        backend_client_cert="/etc/shield/client.crt",
        backend_client_key="/etc/shield/client.key",
    )
    context = object()
    build_context.return_value = context
    response = urlopen.return_value.__enter__.return_value

    RemediationWorker(device_config=config, exporter=Mock())._claim()

    build_context.assert_called_once_with(config)
    assert urlopen.call_args.kwargs["context"] is context
    assert urlopen.call_args.kwargs["timeout"] == 2.0
    assert response is not None
