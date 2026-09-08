from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock, patch

from shield.config import DeviceConfig
from shield.watchdog import Watchdog


def _config():
    return DeviceConfig(device_id="dev-1", tenant_id="tenant-1")


@patch("shield.watchdog.publish_runtime_status")
def test_tick_drives_reloader_and_opa_supervisor_independent_of_events(mock_publish):
    reloader = Mock()
    reloader.status.return_value = SimpleNamespace(healthy=True)
    opa_supervisor = Mock()
    policy_engine = Mock()
    policy_engine.health_status.return_value = {"healthy": True}
    policy_engine.probe.return_value = {"healthy": True}
    sensor = Mock()
    sensor.health.return_value = {"attached": True, "lost_events": 0, "last_event_at": None}
    exporter = Mock()
    exporter.health.return_value = {"export_failures": 0, "queue_depth": 0}

    watchdog = Watchdog(
        interval=1.0,
        device_config=_config(),
        policy_engine=policy_engine,
        reloader=reloader,
        opa_supervisor=opa_supervisor,
        exporter=exporter,
        sensor=sensor,
    )

    watchdog.tick()

    reloader.check_and_reload.assert_called_once()
    opa_supervisor.restart_if_unhealthy.assert_called_once()
    policy_engine.probe.assert_called_once()
    sensor.health.assert_called_once()
    exporter.health.assert_called_once()
    mock_publish.assert_called_once()
    _, kwargs = mock_publish.call_args
    assert kwargs["sensors_status"] == {"attached": True, "lost_events": 0, "last_event_at": None}
    assert kwargs["exporter_status_detail"] == {"export_failures": 0, "queue_depth": 0}
    assert kwargs["did_preflight_detail"] is None


@patch("shield.watchdog.publish_runtime_status")
def test_tick_republishes_the_same_startup_preflight_result_unchanged(mock_publish):
    """did_preflight is computed once at `shield run` startup (cli.py), not re-checked
    every tick -- confirms Watchdog just forwards whatever it was constructed with."""
    policy_engine = Mock()
    policy_engine.health_status.return_value = {"healthy": True}
    sensor = Mock()
    sensor.health.return_value = {"attached": True}
    preflight_result = {"did": "did:test:agent", "did_loaded": True, "bcc_middleware_reachable": True}

    watchdog = Watchdog(
        interval=1.0,
        device_config=_config(),
        policy_engine=policy_engine,
        reloader=None,
        opa_supervisor=None,
        exporter=None,
        sensor=sensor,
        did_preflight_status=preflight_result,
    )

    watchdog.tick()
    watchdog.tick()

    assert mock_publish.call_count == 2
    for call in mock_publish.call_args_list:
        assert call.kwargs["did_preflight_detail"] is preflight_result


@patch("shield.watchdog.publish_runtime_status")
def test_tick_tolerates_missing_optional_dependencies(mock_publish):
    policy_engine = Mock()
    policy_engine.health_status.return_value = {"healthy": None}
    policy_engine.policy_hash = ""
    policy_engine.policy_version = ""
    del policy_engine.probe  # simulate an older PolicyEngine without an active probe
    sensor = object()  # no health() method at all

    watchdog = Watchdog(
        interval=1.0,
        device_config=_config(),
        policy_engine=policy_engine,
        reloader=None,
        opa_supervisor=None,
        exporter=None,
        sensor=sensor,
    )

    watchdog.tick()  # must not raise

    mock_publish.assert_called_once()
    _, kwargs = mock_publish.call_args
    assert kwargs["sensors_status"] == {"attached": True}
    assert kwargs["exporter_status_detail"] == {"enabled": False}


def test_start_stop_actually_ticks_on_a_timer():
    policy_engine = Mock()
    policy_engine.health_status.return_value = {"healthy": True}
    sensor = Mock()
    sensor.health.return_value = {"attached": True, "lost_events": 0, "last_event_at": None}

    with patch("shield.watchdog.publish_runtime_status") as mock_publish:
        watchdog = Watchdog(
            interval=0.01,
            device_config=_config(),
            policy_engine=policy_engine,
            reloader=None,
            opa_supervisor=None,
            exporter=None,
            sensor=sensor,
        )
        watchdog.start()
        import time

        time.sleep(0.05)
        watchdog.stop()

    assert mock_publish.call_count >= 1
