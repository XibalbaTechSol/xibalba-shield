"""A local, on-disk copy of the watchdog's sensor health, for other processes on this device.

Why a file
----------
`shield run` and `shield gate-daemon` are separate processes. The watchdog (`shield/watchdog.py`)
already asks the sensor for its health every tick, but until this module the only place that answer
went was an HTTP POST to Shield's backend (`runtime_status.publish_runtime_status`). Nothing on the
device could act on it, which is how a sensor could be down for days with the gate none the wiser.

With `shield run --sensor-status-file PATH` the watchdog also writes that same `sensors` dict here,
once per tick, and `shield.gate_zone.SensorSilenceZoneProvider` reads it. The file is the heartbeat:
a watchdog that has stopped ticking stops rewriting it, and its `written_at` goes stale.

Format (`v` 1): ``{"v": 1, "written_at": <unix seconds>, "pid": <writer pid>, "sensors": {...}}``,
where `sensors` is exactly what the watchdog publishes to the backend -- the sensor's own `health()`
dict, or ``{"attached": false, "error": "..."}`` when that call raised.

What this does not prove
------------------------
The file is written by the same user the sensor runs as, with no signature. A process that can write
it can forge a fresh, healthy status; mode 0600 keeps *other* users out, not the owner. It is a
liveness signal against a sensor that died or was stopped, not a tamper-proof attestation.
"""

from __future__ import annotations

import json
import math
import os
import time
from pathlib import Path
from typing import Any, Mapping, Optional

SENSOR_STATUS_VERSION = 1


class SensorStatusError(Exception):
    """The status file exists but does not hold a status this version understands."""


def write_sensor_status(path: Path | str, sensors_status: Mapping[str, Any], *, now: Optional[float] = None) -> None:
    """Atomically replace `path` with the current sensor status (0600). Raises `OSError` on failure.

    Written to a sibling temp file and renamed over the target, so a reader sees either the previous
    complete status or the new one, never a half-written file it would have to call unreadable.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {
            "v": SENSOR_STATUS_VERSION,
            "written_at": time.time() if now is None else now,
            "pid": os.getpid(),
            "sensors": dict(sensors_status),
        },
        sort_keys=True, default=str,
    ).encode("utf-8")
    temp = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
        os.replace(temp, target)
    except BaseException:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise


def read_sensor_status(path: Path | str) -> dict[str, Any]:
    """Return the status at `path`.

    Raises `FileNotFoundError` when there is no file, `OSError` when it cannot be read, and
    `SensorStatusError` when it is not a well-formed status. The three are kept apart because
    "never written" and "written, then damaged" are different facts to a caller.
    """
    raw = Path(path).read_bytes()
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SensorStatusError(f"sensor status file is not UTF-8 JSON: {exc}") from exc
    if not isinstance(document, dict) or document.get("v") != SENSOR_STATUS_VERSION:
        raise SensorStatusError("sensor status file is not a version 1 status object")
    written_at = document.get("written_at")
    # bool is an int in Python; `true` is not a timestamp.
    # And Python's json accepts NaN/Infinity, which compare false against every threshold: a NaN
    # timestamp would be neither stale nor from the future, i.e. fresh forever.
    if isinstance(written_at, bool) or not isinstance(written_at, (int, float)) or not math.isfinite(written_at):
        raise SensorStatusError("sensor status file has no finite numeric written_at")
    if not isinstance(document.get("sensors"), dict):
        raise SensorStatusError("sensor status file has no sensors object")
    return document
