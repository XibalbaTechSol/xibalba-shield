"""Bounded local OPA supervision for production-style Shield deployments.

This module owns the OPA child process only when explicitly enabled by the caller. The
policy engine remains authoritative and fails closed if OPA is unavailable. A supervisor
restart is therefore recovery plumbing, never an authorization decision.
"""

from __future__ import annotations

import logging
import subprocess
import time
from dataclasses import dataclass
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger("shield.opa_supervisor")


@dataclass(frozen=True)
class OpaSupervisorStatus:
    running: bool
    healthy: bool
    restart_count: int
    last_error: str | None


class OpaSupervisor:
    """Start and supervise one explicitly supplied local OPA command."""

    def __init__(
        self,
        command: list[str],
        health_url: str,
        *,
        startup_timeout: float = 5.0,
        request_timeout: float = 0.5,
        max_restarts: int = 3,
        backoff_seconds: float = 0.25,
    ):
        if not command:
            raise ValueError("OPA supervisor command must not be empty")
        if max_restarts < 0:
            raise ValueError("max_restarts must be non-negative")
        self.command = list(command)
        self.health_url = health_url.rstrip("/")
        self.startup_timeout = startup_timeout
        self.request_timeout = request_timeout
        self.max_restarts = max_restarts
        self.backoff_seconds = backoff_seconds
        self._process: subprocess.Popen[bytes] | None = None
        self._restart_count = 0
        self._last_error: str | None = None

    def _healthy_probe(self) -> bool:
        try:
            request = Request(f"{self.health_url}/health", method="GET")
            with urlopen(request, timeout=self.request_timeout) as response:
                return 200 <= getattr(response, "status", 200) < 300
        except (OSError, URLError) as exc:
            self._last_error = str(exc)
            return False

    def _start_once(self) -> None:
        self._process = subprocess.Popen(self.command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + self.startup_timeout
        while time.monotonic() < deadline:
            if self._process.poll() is not None:
                raise RuntimeError(f"OPA exited during startup with code {self._process.returncode}")
            if self._healthy_probe():
                self._last_error = None
                return
            time.sleep(0.05)
        raise TimeoutError(f"OPA did not become healthy at {self.health_url}")

    def start(self) -> OpaSupervisorStatus:
        if self._process is not None and self._process.poll() is None:
            return self.status()
        self._start_once()
        return self.status()

    def restart_if_unhealthy(self) -> OpaSupervisorStatus:
        if self._process is not None and self._process.poll() is None and self._healthy_probe():
            return self.status()
        if self._restart_count >= self.max_restarts:
            self._last_error = self._last_error or "OPA restart budget exhausted"
            return self.status()
        self.stop()
        delay = self.backoff_seconds * (2 ** self._restart_count)
        if delay:
            time.sleep(delay)
        self._restart_count += 1
        try:
            self._start_once()
        except (OSError, RuntimeError, TimeoutError) as exc:
            self._last_error = str(exc)
            logger.error("OPA supervisor restart failed: %s", exc)
        return self.status()

    def stop(self) -> None:
        if self._process is None or self._process.poll() is not None:
            return
        self._process.terminate()
        try:
            self._process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=2)

    def status(self) -> OpaSupervisorStatus:
        running = self._process is not None and self._process.poll() is None
        return OpaSupervisorStatus(
            running=running,
            healthy=running and self._healthy_probe(),
            restart_count=self._restart_count,
            last_error=self._last_error,
        )

    def __enter__(self) -> "OpaSupervisor":
        self.start()
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.stop()
