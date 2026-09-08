import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

from shield.backend.api import make_handler
from shield.backend.store import ShieldStore


def _request(url, *, method="GET", body=None, token=""):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    if data is not None:
        headers["Content-Type"] = "application/json"
    with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers, method=method), timeout=5) as response:
        return response.status, json.load(response)


def test_device_claims_and_completes_remediation_job(tmp_path):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    enrollment = store.enroll_device(tenant_id="tenant-a", device_id="dev-1", device_role="worker", base_url="http://backend")
    store.request_exporter_remediation(tenant_id="tenant-a", device_id="dev-1", action="retry")
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(store=store, admin_token="admin"))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        status, claimed = _request(
            f"{base}/api/shield/exporter-remediation/next?tenant_id=tenant-a&device_id=dev-1",
            token=enrollment.device_token,
        )
        assert status == 200 and claimed["request"]["status"] == "running"
        request_id = claimed["request"]["id"]
        status, completed = _request(
            f"{base}/api/shield/exporter-remediation/complete", method="POST",
            token=enrollment.device_token,
            body={"tenant_id": "tenant-a", "device_id": "dev-1", "request_id": request_id,
                  "status": "completed", "detail": {"delivered": 1}},
        )
        assert status == 200 and completed["request"]["status"] == "completed"
        _, queue = _request(f"{base}/api/shield/exporter-remediation?tenant_id=tenant-a", token="admin")
        assert queue["attempts"][0]["detail"] == {"delivered": 1}
    finally:
        server.shutdown()
        store.close()
