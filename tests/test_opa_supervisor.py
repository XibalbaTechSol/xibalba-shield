from __future__ import annotations

from unittest.mock import Mock, patch

from shield.opa_supervisor import OpaSupervisor


class _Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None


class _Process:
    def __init__(self):
        self.returncode = None
        self.terminated = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode


@patch("shield.opa_supervisor.urlopen", return_value=_Response())
@patch("shield.opa_supervisor.subprocess.Popen")
def test_supervisor_starts_and_stops_child(mock_popen, _urlopen):
    process = _Process()
    mock_popen.return_value = process
    supervisor = OpaSupervisor(["opa", "run"], "http://127.0.0.1:8181", startup_timeout=0.01)

    status = supervisor.start()

    assert status.running is True
    assert status.healthy is True
    mock_popen.assert_called_once_with(["opa", "run"], stdout=-3, stderr=-3)
    supervisor.stop()
    assert process.terminated is True


@patch("shield.opa_supervisor.urlopen", side_effect=OSError("connection refused"))
@patch("shield.opa_supervisor.subprocess.Popen")
def test_supervisor_enforces_restart_budget(mock_popen, _urlopen):
    process = _Process()
    mock_popen.return_value = process
    supervisor = OpaSupervisor(["opa"], "http://127.0.0.1:8181", max_restarts=0)
    supervisor._process = process

    status = supervisor.restart_if_unhealthy()

    assert status.running is True
    assert status.healthy is False
    assert status.restart_count == 0
    assert "connection refused" in (status.last_error or "")
    mock_popen.assert_not_called()


def test_supervisor_rejects_empty_command():
    try:
        OpaSupervisor([], "http://127.0.0.1:8181")
    except ValueError as exc:
        assert "must not be empty" in str(exc)
    else:
        raise AssertionError("expected empty command rejection")
