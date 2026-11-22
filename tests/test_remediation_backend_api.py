import json
import threading
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import ThreadingHTTPServer

import pytest

from shield.backend.api import make_handler
from shield.backend.store import ShieldStore


def _request(url, *, method="GET", body=None, token=""):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8")
        try:
            parsed = json.loads(err_body)
        except Exception:
            parsed = {"error": err_body}
        return exc.code, parsed


def test_remediation_plans_backend_api_lifecycle(tmp_path):
    store = ShieldStore(tmp_path / "shield.sqlite3")
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(store=store, admin_token="admin-secret"))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"

    try:
        # 1. Unauthenticated request rejected (401)
        status, resp = _request(f"{base}/api/shield/remediation/plans?tenant_id=tenant-test")
        assert status == 401

        # 2. List plans empty initially
        status, resp = _request(f"{base}/api/shield/remediation/plans?tenant_id=tenant-test", token="admin-secret")
        assert status == 200
        assert resp["status"] == "ok"
        assert resp["plans"] == []

        # 3. Create a remediation plan via POST
        plan_doc = {
            "schema": "xibalba.shield.remediation-plan.v1",
            "executed": False,
            "actions": [
                {
                    "type": "upgrade_package",
                    "package": "requests",
                    "installed_version": "2.25.0",
                    "recommended_version": "2.31.0",
                    "cve": "CVE-2023-32681",
                }
            ],
            "estimated_impact": "low",
        }
        status, create_resp = _request(
            f"{base}/api/shield/remediation/plans",
            method="POST",
            body={"tenant_id": "tenant-test", "plan": plan_doc},
            token="admin-secret",
        )
        assert status == 201
        assert create_resp["status"] == "ok"
        assert "plan_id" in create_resp
        assert create_resp["executed"] is False
        plan_id = create_resp["plan_id"]

        # 4. Fetch the plan by plan_id
        status, get_resp = _request(
            f"{base}/api/shield/remediation/plans/{plan_id}?tenant_id=tenant-test",
            token="admin-secret",
        )
        assert status == 200
        assert get_resp["status"] == "ok"
        plan_record = get_resp["plan"]
        assert plan_record["plan_id"] == plan_id
        assert plan_record["status"] == "pending"
        assert plan_record["tenant_id"] == "tenant-test"
        assert plan_record["executed"] is False
        assert len(plan_record["plan"]["actions"]) == 1

        # 5. Fetch non-existent plan (404)
        status, not_found_resp = _request(
            f"{base}/api/shield/remediation/plans/non-existent-id?tenant_id=tenant-test",
            token="admin-secret",
        )
        assert status == 404

        # 6. Invalid transition status (400)
        status, bad_status_resp = _request(
            f"{base}/api/shield/remediation/plans/{plan_id}/transition",
            method="POST",
            body={"tenant_id": "tenant-test", "status": "executed"},
            token="admin-secret",
        )
        assert status == 400

        # 7. Approve transition (200)
        status, trans_resp = _request(
            f"{base}/api/shield/remediation/plans/{plan_id}/transition",
            method="POST",
            body={"tenant_id": "tenant-test", "status": "approved", "reason": "Security review verified"},
            token="admin-secret",
        )
        assert status == 200
        assert trans_resp["status"] == "ok"
        updated_plan = trans_resp["plan"]
        assert updated_plan["status"] == "approved"
        assert updated_plan["executed"] is False
        assert len(updated_plan["audit"]) == 1
        assert updated_plan["audit"][-1]["status"] == "approved"
        assert updated_plan["audit"][-1]["actor"] == "operator"
        assert updated_plan["audit"][-1]["actor_id"] == "admin"

        # 8. List plans filtered by status
        status, list_approved = _request(
            f"{base}/api/shield/remediation/plans?tenant_id=tenant-test&status=approved",
            token="admin-secret",
        )
        assert status == 200
        assert len(list_approved["plans"]) == 1
        assert list_approved["plans"][0]["plan_id"] == plan_id

        status, list_rejected = _request(
            f"{base}/api/shield/remediation/plans?tenant_id=tenant-test&status=rejected",
            token="admin-secret",
        )
        assert status == 200
        assert len(list_rejected["plans"]) == 0
    finally:
        server.shutdown()
        store.close()
