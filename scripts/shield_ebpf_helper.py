#!/usr/bin/env python3
"""Root-owned BCC bridge; policy and enforcement stay in the main agent."""
from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import time
from datetime import datetime, timezone
from pathlib import Path

from shield.sensors.ebpf.loader import LinuxEbpfSensor


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", default="/run/xibalba-shield/ebpf.sock")
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--tenant-id", default="")
    args = parser.parse_args()
    path = Path(args.socket)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    sensor = LinuxEbpfSensor(device_id=args.device_id, tenant_id=args.tenant_id)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
    server.listen(1)
    try:
        while True:
            conn, _ = server.accept()
            # A client restart must not take down the privileged probe.  Keep
            # accepting connections after a broken pipe and emit a heartbeat
            # during quiet periods so the unprivileged client can distinguish
            # a healthy, idle probe from a dead socket.
            with conn:
                stream = conn.makefile("w", encoding="utf-8")
                last_heartbeat = 0.0
                try:
                    while True:
                        emitted = False
                        for event in sensor.poll(timeout_ms=1000):
                            stream.write(json.dumps({"type": "process_activity", "event": event.to_dict()}) + "\n")
                            emitted = True
                        now = time.monotonic()
                        if not emitted and now - last_heartbeat >= 5.0:
                            stream.write(json.dumps({
                                "type": "heartbeat",
                                "time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                            }) + "\n")
                            last_heartbeat = now
                        stream.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    # Return to accept() without unloading the kernel sensor.
                    pass
                finally:
                    stream.close()
    finally:
        server.close()
        path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
