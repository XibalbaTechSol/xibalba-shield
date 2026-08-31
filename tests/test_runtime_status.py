from unittest.mock import patch

from shield.config import DeviceConfig
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
def test_runtime_status_posts_authenticated_health(mock_urlopen):
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
