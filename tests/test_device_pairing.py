"""Tests for hybrid endpoint device pairing and installation."""
from __future__ import annotations

import json
import secrets
import threading
import time
import urllib.parse
import urllib.request
from http import HTTPStatus
from pathlib import Path
from typing import Any

import pytest

from shield.backend.api import SESSION_COOKIE_NAME, run_server
from shield.backend.store import ShieldStore
from shield.device_pairing import (
    DevicePairingFlow,
    detect_device_id,
    detect_device_type,
    load_or_create_device_did,
)
from shield.cli import main


def test_device_detection():
    device_id = detect_device_id()
    assert isinstance(device_id, str)
    assert len(device_id) > 0

    device_type = detect_device_type()
    assert isinstance(device_type, str)
    assert any(k in device_type.lower() for k in ("real", "physical", "virtual", "container", "wsl", "vm"))


def test_load_or_create_device_did(tmp_path: Path):
    shield_home = tmp_path / ".shield"
    agent_did, pub_b64, kp = load_or_create_device_did(shield_home)

    assert agent_did.startswith("did:integrity:")
    assert len(pub_b64) > 10
    key_path = shield_home / "private_key.pem"
    assert key_path.exists()
    assert key_path.stat().st_mode & 0o777 == 0o600

    # Running a second time reloads the exact same DID
    agent_did_2, pub_b64_2, kp_2 = load_or_create_device_did(shield_home)
    assert agent_did_2 == agent_did
    assert pub_b64_2 == pub_b64


def test_store_device_pairing_lifecycle(tmp_path: Path):
    db_path = tmp_path / "pairing_test.db"
    store = ShieldStore(str(db_path))

    # 1. Request pairing
    req = store.create_device_pairing_request(
        device_id="test-endpoint-dev-01",
        device_name="Operator Workstation",
        device_type="physical",
        agent_did="did:integrity:abcdef1234567890",
        callback_url="http://127.0.0.1:8436/callback",
    )

    code = req["code"]
    device_code = req["device_code"]
    assert code.startswith("SHLD-")
    assert len(device_code) > 20
    assert req["status"] == "pending"

    # 2. Get pairing by user code
    fetched = store.get_device_pairing_request(code)
    assert fetched is not None
    assert fetched["device_id"] == "test-endpoint-dev-01"
    assert fetched["device_name"] == "Operator Workstation"
    assert fetched["device_type"] == "physical"
    assert fetched["status"] == "pending"

    # 3. Poll status before approval
    poll_1 = store.poll_device_pairing_status(code)
    assert poll_1["status"] == "pending"
    assert "device_token" not in poll_1

    # 4. Approve pairing
    approved = store.approve_device_pairing_request(
        code=code,
        tenant_id="tenant-acme",
        account_id="user@acme.com",
    )
    assert approved["ok"] is True
    assert approved["tenant_id"] == "tenant-acme"
    assert isinstance(approved["device_token"], str) and len(approved["device_token"]) > 20

    # 5. Poll status after approval (can use either device_code or user code)
    poll_2 = store.poll_device_pairing_status(device_code)
    assert poll_2["status"] == "approved"
    assert poll_2["tenant_id"] == "tenant-acme"
    assert poll_2["device_token"] == approved["device_token"]
    assert poll_2["device_id"] == "test-endpoint-dev-01"
    assert poll_2["agent_did"] == "did:integrity:abcdef1234567890"

    # 6. Verify enrolled device record in store
    dev = store.get_device(tenant_id="tenant-acme", device_id="test-endpoint-dev-01")
    assert dev is not None
    assert dev["tenant_id"] == "tenant-acme"
    assert dev["integrity_agent_id"] == "did:integrity:abcdef1234567890"
    proof = json.loads(dev["binding_proof"])
    assert proof["device_type"] == "physical"
    assert proof["device_confinement"] == "confined_to_endpoint"
    assert proof["device_hmac"] is not None


def test_backend_pairing_endpoints_and_scripts(tmp_path: Path):
    db_path = tmp_path / "backend_pairing.db"
    store = ShieldStore(str(db_path))

    # Pre-create an authenticated operator account + session
    account, session_token = store.authenticate_or_create_oauth_account(
        email="dev.operator@xibalba.io",
        provider="google",
        provider_user_id="google-sub-555",
        display_name="Dev Operator",
    )
    tenant_id = account["tenant_id"]

    admin_token = secrets.token_hex(16)
    server = run_server(
        host="127.0.0.1",
        port=0,
        db_path=db_path,
        admin_token=admin_token,
        auth_secret="test-auth-secret",
    )
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        # 1. Test GET /install.sh
        req = urllib.request.Request(f"{base_url}/install.sh")
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode()
            assert "#!/usr/bin/env bash" in content
            assert "shield install" in content

        # 2. Test GET /install.ps1
        req = urllib.request.Request(f"{base_url}/install.ps1")
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode()
            assert "PowerShell" in content
            assert "shield install" in content

        # 3. Test POST /api/shield/device/pair/request
        req_body = {
            "device_id": "laptop-thinkpad-x1",
            "device_name": "Alice ThinkPad",
            "device_type": "physical",
            "agent_did": "did:integrity:thinkpad_device_did_001",
            "callback_url": "http://127.0.0.1:8436/callback",
        }
        req = urllib.request.Request(
            f"{base_url}/api/shield/device/pair/request",
            data=json.dumps(req_body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            assert data["ok"] is True
            code = data["code"]
            device_code = data["device_code"]
            assert code.startswith("SHLD-")
            assert "verification_uri" in data
            assert f"code={code}" in data["verification_uri"]

        # 4. Test GET /api/shield/device/pair/{code}
        req = urllib.request.Request(f"{base_url}/api/shield/device/pair/{code}")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            assert data["code"] == code
            assert data["device_name"] == "Alice ThinkPad"
            assert data["device_type"] == "physical"
            assert data["agent_did"] == "did:integrity:thinkpad_device_did_001"
            assert data["status"] == "pending"

        # 5. Unauthenticated POST approve fails with 401
        req = urllib.request.Request(
            f"{base_url}/api/shield/device/pair/{code}/approve",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req)
        assert exc_info.value.code == HTTPStatus.UNAUTHORIZED

        # 6. Authenticated POST approve succeeds
        req = urllib.request.Request(
            f"{base_url}/api/shield/device/pair/{code}/approve",
            data=b"{}",
            headers={
                "Content-Type": "application/json",
                "Cookie": f"{SESSION_COOKIE_NAME}={session_token}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            assert data["ok"] is True
            assert data["device_id"] == "laptop-thinkpad-x1"
            assert data["tenant_id"] == tenant_id
            assert isinstance(data["device_token"], str) and len(data["device_token"]) > 20
            assert data["callback_url"] == "http://127.0.0.1:8436/callback"

        # 7. Device polls /status and gets approval details
        status_url = f"{base_url}/api/shield/device/pair/{device_code}/status"
        req = urllib.request.Request(status_url)
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            assert data["status"] == "approved"
            assert isinstance(data["device_token"], str) and len(data["device_token"]) > 20
            assert data["tenant_id"] == tenant_id
            assert data["agent_did"] == "did:integrity:thinkpad_device_did_001"

        # 8. Check device listing via API returns hybrid architecture
        devices_req = urllib.request.Request(
            f"{base_url}/api/shield/devices?tenant_id={tenant_id}",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={session_token}"},
        )
        with urllib.request.urlopen(devices_req) as resp:
            data = json.loads(resp.read().decode())
            dev_list = data.get("devices", [])
            matching = [d for d in dev_list if d.get("device_id") == "laptop-thinkpad-x1"]
            assert len(matching) == 1
            device_entry = matching[0]
            assert device_entry["device_type"] == "physical"
            assert device_entry["device_confinement"] == "confined_to_endpoint"
            hybrid = device_entry.get("hybrid_architecture", {})
            assert hybrid.get("mode") == "hybrid"
            assert hybrid.get("local_enforcement", {}).get("status") == "active"
            assert hybrid.get("local_enforcement", {}).get("confinement") == "confined_to_endpoint"
            assert hybrid.get("cloud_reasoning", {}).get("status") in ("configured", "not_configured")

    finally:
        server.shutdown()
        server.server_close()


def test_cli_pair_and_install_help():
    with pytest.raises(SystemExit) as exc:
        main(["pair", "--help"])
    assert exc.value.code == 0

    with pytest.raises(SystemExit) as exc:
        main(["install", "--help"])
    assert exc.value.code == 0
