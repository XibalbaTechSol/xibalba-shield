import json
import time
from pathlib import Path
import pytest

from shield.cli import main
from shield.advisories import sign_advisory_source


def test_cli_inventory_basic(capsys):
    rc = main(["inventory", "--max-processes", "10", "--max-packages", "10"])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["schema"] == "xibalba.shield.inventory.v1"
    assert "os" in data
    assert "hardware" in data
    assert "packages" in data
    assert "posture" in data
    assert "snapshot_hash" in data


def test_cli_inventory_hash_only(capsys):
    rc = main(["inventory", "--hash-only"])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "snapshot_hash" in data
    assert "os" not in data
    assert "packages" not in data


def test_cli_inventory_with_fresh_advisories_and_remediation_plan(tmp_path, capsys):
    advisory_file = tmp_path / "advisories.json"
    doc = {
        "updated_at": time.time(),
        "advisories": [
            {
                "id": "SEC-001",
                "package": "bash",
                "version_range": ">= 1.0.0",
                "severity": "high",
                "summary": "Sample bash advisory",
                "fixed_version": "99.0.0",
            }
        ],
    }
    advisory_file.write_text(json.dumps(doc), encoding="utf-8")

    rc = main([
        "inventory",
        "--advisory-source", str(advisory_file),
        "--remediation-plan",
        "--maintenance-window", "02:00-04:00UTC",
    ])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "vulnerability" in data
    assert data["vulnerability"]["status"] == "matched"
    assert "remediation_plan" in data["vulnerability"]
    plan = data["vulnerability"]["remediation_plan"]
    assert plan["status"] == "approval_required"
    assert plan["executed"] is False
    assert plan["maintenance_window"] == "02:00-04:00UTC"


def test_cli_inventory_stale_advisories_fails_unavailable(tmp_path, capsys):
    stale_file = tmp_path / "stale_advisories.json"
    doc = {
        "updated_at": time.time() - 200000,
        "advisories": [],
    }
    stale_file.write_text(json.dumps(doc), encoding="utf-8")

    rc = main(["inventory", "--advisory-source", str(stale_file), "--advisory-max-age", "3600"])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["vulnerability"]["status"] == "unavailable"
    assert "stale" in data["vulnerability"]["error"].lower()


def test_cli_inventory_corrupt_advisory_fails_unavailable(tmp_path, capsys):
    corrupt_file = tmp_path / "corrupt.json"
    corrupt_file.write_text("{invalid json", encoding="utf-8")

    rc = main(["inventory", "--advisory-source", str(corrupt_file)])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["vulnerability"]["status"] == "unavailable"


def test_cli_inventory_signed_advisories_and_invalid_signature(tmp_path, capsys):
    signed_file = tmp_path / "signed_advisories.json"
    key = "secret-test-key"
    doc = {
        "updated_at": time.time(),
        "signer": "xibalba-security-feed",
        "advisories": [
            {
                "id": "SEC-002",
                "package": "bash",
                "version": "1.0",
                "severity": "low",
                "summary": "Sample advisory",
                "fixed_version": "1.1",
            }
        ],
    }
    signed_doc = sign_advisory_source(doc, key, algorithm="hmac-sha256")
    signed_file.write_text(json.dumps(signed_doc), encoding="utf-8")

    # Valid key
    rc = main([
        "inventory",
        "--advisory-source", str(signed_file),
        "--advisory-key", key,
        "--require-advisory-signature",
    ])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["vulnerability"]["status"] == "matched"

    # Invalid key
    rc = main([
        "inventory",
        "--advisory-source", str(signed_file),
        "--advisory-key", "wrong-key",
        "--require-advisory-signature",
    ])
    assert rc == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["vulnerability"]["status"] == "unavailable"
    assert "invalid advisory signature" in data["vulnerability"]["error"].lower()


def test_cli_remediation_lifecycle(tmp_path, capsys):
    store_path = tmp_path / "remediation.db"
    plan_path = tmp_path / "plan.json"
    plan_content = {
        "actions": [
            {"package": "libc6", "from_version": "2.35", "to_version": "2.36", "priority": 3}
        ],
        "executed": False,
    }
    plan_path.write_text(json.dumps(plan_content), encoding="utf-8")

    # Create plan
    rc = main(["remediation", "create", "--store", str(store_path), "--plan", str(plan_path)])
    assert rc == 0
    captured = capsys.readouterr()
    res = json.loads(captured.out)
    assert res["executed"] is False
    plan_id = res["plan_id"]
    assert plan_id

    # Show plan
    rc = main(["remediation", "show", "--store", str(store_path), "--plan-id", plan_id])
    assert rc == 0
    captured = capsys.readouterr()
    shown = json.loads(captured.out)
    assert shown["status"] == "pending"
    assert shown["executed"] is False

    # Approve plan
    rc = main([
        "remediation", "approved",
        "--store", str(store_path),
        "--plan-id", plan_id,
        "--actor", "alice-security-ops",
        "--reason", "maintenance window approved",
    ])
    assert rc == 0
    captured = capsys.readouterr()
    approved = json.loads(captured.out)
    assert approved["status"] == "approved"
    assert approved["executed"] is False
    assert len(approved["audit"]) == 1
    assert approved["audit"][0]["actor"] == "alice-security-ops"

    # Reject plan
    rc = main([
        "remediation", "rejected",
        "--store", str(store_path),
        "--plan-id", plan_id,
        "--actor", "lead-engineer",
        "--reason", "postponed",
    ])
    assert rc == 0
    captured = capsys.readouterr()
    rejected = json.loads(captured.out)
    assert rejected["status"] == "rejected"
    assert len(rejected["audit"]) == 2

    # Show missing plan returns exit code 2
    rc = main(["remediation", "show", "--store", str(store_path), "--plan-id", "nonexistent"])
    assert rc == 2
