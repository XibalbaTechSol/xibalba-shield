import json
import socket
import threading

from shield.sensors.privileged_socket import PrivilegedProcessSensor


def test_privileged_sensor_decodes_process_activity(tmp_path):
    path = str(tmp_path / "ebpf.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(1)

    def serve():
        conn, _ = server.accept()
        with conn:
            conn.sendall((json.dumps({
                "type": "heartbeat",
                "time": "2026-01-01T00:00:00Z",
            }) + "\n").encode())
            conn.sendall((json.dumps({
                "type": "process_activity",
                "event": {
                    "class": "process_activity",
                    "time": "2026-01-01T00:00:00Z",
                    "device_id": "dev-1",
                    "tenant_id": "tenant-a",
                    "process": {"pid": 42, "name": "sh", "exe_path": "/bin/sh", "cmdline": "", "hash_sha256": "", "ppid": 1, "parent_name": "init"},
                    "activity": {"type": "launch", "severity": "medium", "outcome": "success"},
                },
            }) + "\n").encode())
        server.close()

    threading.Thread(target=serve, daemon=True).start()
    sensor = PrivilegedProcessSensor(path)
    event = next(sensor.events())
    assert event.device_id == "dev-1"
    assert event.process.pid == 42
    assert event.process.exe_path == "/bin/sh"
    assert sensor.health()["last_heartbeat_at"] == "2026-01-01T00:00:00Z"
