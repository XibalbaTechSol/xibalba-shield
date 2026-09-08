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
        did_preflight_status: dict[str, Any] | None = None,
    ) -> None:
        self._interval = interval
        self._device_config = device_config
        self._policy_engine = policy_engine
        self._reloader = reloader
        self._opa_supervisor = opa_supervisor
        self._exporter = exporter
        self._sensor = sensor
        # Computed once at `shield run` startup (see cli.py) via
        # integrity_exporter.check_did_preflight -- republished unchanged on every tick
        # rather than re-checked, since DID load/reachability isn't tick-timescale state.
        self._did_preflight_status = did_preflight_status
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
        threading.

        Each sub-check below is individually try/excepted -- a chaos scenario this
        exists to catch (workstream I's "sensor unload": a dead sensor whose own
        `health()` call raises, not just returns `attached: False`) must never abort
        the whole tick before `publish_runtime_status` runs. Previously it did: one
        raising sub-check meant NO status was published that cycle, so the dashboard
        kept showing stale "healthy" data during exactly the failure this watchdog
        exists to surface -- the opposite of Gate 6's "known limitations visible to
        operators." Each failure is now reported as real status, not silence."""
        if self._reloader is not None:
            try:
                self._reloader.check_and_reload()
            except Exception:  # noqa: BLE001
                logger.exception("watchdog: reloader.check_and_reload() failed")
        if self._opa_supervisor is not None:
            try:
                self._opa_supervisor.restart_if_unhealthy()
            except Exception:  # noqa: BLE001
                logger.exception("watchdog: opa_supervisor.restart_if_unhealthy() failed")
        # Independent of the above: probe OPA directly rather than relying on
        # `evaluate()` traffic to keep `_opa_healthy` fresh (see PolicyEngine.probe's
        # docstring -- this is what actually prevents a stale-healthy OPA reading on an
        # idle sensor stream).
        probe = getattr(self._policy_engine, "probe", None)
        if probe is not None:
            try:
                probe()
            except Exception:  # noqa: BLE001
                logger.exception("watchdog: policy_engine.probe() failed")

        sensor_health = getattr(self._sensor, "health", None)
        if sensor_health is not None:
            try:
                sensors_status = sensor_health()
            except Exception as exc:  # noqa: BLE001
                logger.exception("watchdog: sensor.health() failed -- sensor may have died or detached")
                sensors_status = {"attached": False, "error": str(exc)}
        else:
            sensors_status = {"attached": True}

        exporter_status: dict[str, Any] | None
        if self._exporter is not None:
            # Drains the durable export spool (see integrity_exporter/spool.py) on this
            # same timer, independent of new decisions arriving -- an outage that stops
            # all traffic must not also stop retrying what's already queued.
            replay_pending = getattr(self._exporter, "replay_pending", None)
            if replay_pending is not None:
                try:
                    replay_pending()
                except Exception:  # noqa: BLE001
                    logger.exception("watchdog: exporter.replay_pending() failed")
            exporter_health = getattr(self._exporter, "health", None)
            if exporter_health is not None:
                try:
                    exporter_status = exporter_health()
                except Exception as exc:  # noqa: BLE001
                    logger.exception("watchdog: exporter.health() failed")
                    exporter_status = {"error": str(exc)}
            else:
                exporter_status = {}
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
            did_preflight_detail=self._did_preflight_status,
        )
