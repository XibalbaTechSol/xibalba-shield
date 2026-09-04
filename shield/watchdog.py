"""Watchdog — periodic health/degraded-state telemetry, independent of event traffic.

`docs/PRODUCTION_READINESS_PLAN.md` workstream B: "Add supervisor/watchdog and
health/degraded-state telemetry for OPA, sensors, exporter, and queue" and "prevent
stale 'healthy' status after sensor or policy failure." Before this module, every
health check (`PolicyHotReloader.check_and_reload`, `OpaSupervisor.restart_if_unhealthy`,
`publish_runtime_status`) ran only as a side effect of `shield run`'s per-event loop
(`cli.py`) -- if the sensor stream stalled or died, every one of those checks froze at
whatever they'd last reported. This class is the single owner of that periodic
maintenance, running on its own timer thread instead of piggybacking on event handling.

`PolicyHotReloader`'s own docstring already anticipated this ("likely a periodic timer
in agent_core") -- this finishes that stated intent rather than inventing a new
direction. It is also the *only* caller of `check_and_reload()`/
`restart_if_unhealthy()` once wired into `cli.py`, so there is no concurrent-call race
to reason about between this thread and the main sensor loop.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from .config import DeviceConfig
from .runtime_status import publish_runtime_status

logger = logging.getLogger("shield.watchdog")


class Watchdog:
    """Ticks every `interval` seconds on a daemon thread until `stop()` is called."""

    def __init__(
        self,
        *,
        interval: float,
        device_config: DeviceConfig,
        policy_engine: Any,
        reloader: Any | None,
        opa_supervisor: Any | None,
        exporter: Any | None,
        sensor: Any,
    ) -> None:
        self._interval = interval
        self._device_config = device_config
        self._policy_engine = policy_engine
        self._reloader = reloader
        self._opa_supervisor = opa_supervisor
        self._exporter = exporter
        self._sensor = sensor
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="shield-watchdog", daemon=True)
        self._thread.start()

    def stop(self, join_timeout: float = 2.0) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=join_timeout)
            self._thread = None

    def _run(self) -> None:
        while not self._stop_event.wait(self._interval):
            try:
                self.tick()
            except Exception:  # noqa: BLE001 -- a watchdog tick must never crash the process
                logger.exception("watchdog tick failed")

    def tick(self) -> None:
        """One maintenance pass: hot-reload check, OPA restart-if-unhealthy, and a
        fresh status publish covering policy/opa/sensors/exporter. Public (not just
        `_run`'s private target) so tests can drive it deterministically without
        threading."""
        if self._reloader is not None:
            self._reloader.check_and_reload()
        if self._opa_supervisor is not None:
            self._opa_supervisor.restart_if_unhealthy()
        # Independent of the above: probe OPA directly rather than relying on
        # `evaluate()` traffic to keep `_opa_healthy` fresh (see PolicyEngine.probe's
        # docstring -- this is what actually prevents a stale-healthy OPA reading on an
        # idle sensor stream).
        probe = getattr(self._policy_engine, "probe", None)
        if probe is not None:
            probe()

        sensor_health = getattr(self._sensor, "health", None)
        sensors_status = sensor_health() if sensor_health is not None else {"attached": True}

        exporter_status: dict[str, Any] | None
        if self._exporter is not None:
            exporter_health = getattr(self._exporter, "health", None)
            exporter_status = exporter_health() if exporter_health is not None else {}
        else:
            exporter_status = {"enabled": False}

        policy_status = (
            self._reloader.status().__dict__
            if self._reloader is not None
            else {
                "healthy": bool(self._policy_engine.policy_hash),
                "active_policy_version": self._policy_engine.policy_version,
                "active_policy_hash": self._policy_engine.policy_hash,
            }
        )

        publish_runtime_status(
            device_config=self._device_config,
            policy_status=policy_status,
            opa_status=self._policy_engine.health_status(),
            sensors_status=sensors_status,
            exporter_status_detail=exporter_status,
        )
