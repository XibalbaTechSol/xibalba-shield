import json
from pathlib import Path
from unittest.mock import patch

from scripts.enroll_device import enroll


class Response:
    status = 201

    def read(self):
        return json.dumps({"device_config": {"device_id": "desktop", "tenant_id": "tenant", "device_token": "secret"}}).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None


def test_enroll_writes_private_config_atomically(tmp_path):
    output = tmp_path / ".xibalba-shield" / "device.json"
    with patch("scripts.enroll_device.urlopen", return_value=Response()):
        config = enroll(backend_url="http://backend", admin_token="admin", tenant_id="tenant", device_id="desktop", device_role="workstation", output=output)
    assert config["device_token"] == "secret"
    assert json.loads(output.read_text())["device_id"] == "desktop"
    assert output.stat().st_mode & 0o777 == 0o600
