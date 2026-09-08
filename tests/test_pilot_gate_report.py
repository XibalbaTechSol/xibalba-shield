"""Coverage for scripts/pilot_gate_report.py's new adversarial gate (item 6). The other
gates (`_hardening_gate`, `_installer_gate`, `_burn_in_gate`, `_gate_from_status`) predate
this session and had no test coverage before either; this file scopes to what item 6
actually added rather than retrofitting the whole script."""

from __future__ import annotations

import json

from scripts.pilot_gate_report import _adversarial_gate, main


def test_adversarial_gate_blocked_without_an_artifact():
    gate = _adversarial_gate(None)
    assert gate.status == "BLOCKED"


def test_adversarial_gate_passes_on_a_real_passing_artifact():
    gate = _adversarial_gate({
        "status": "pass",
        "duration_sec": 12.3,
        "threat_model_matrix": "docs/design/threat-model-matrix-2026-09-06.md",
    })
    assert gate.status == "PASS"
    assert "threat-model-matrix" in gate.detail


def test_adversarial_gate_fails_on_a_failing_artifact():
    gate = _adversarial_gate({
        "status": "fail",
        "reason": "pytest exited 1 -- see stdout_tail",
    })
    assert gate.status == "FAIL"
    assert "pytest exited 1" in gate.detail


def test_main_includes_the_adversarial_gate_and_fails_the_run_on_a_bad_artifact(tmp_path, capsys):
    artifact_path = tmp_path / "adversarial.json"
    artifact_path.write_text(json.dumps({"status": "fail", "reason": "3 tests failed"}))

    code = main(["--adversarial-artifact", str(artifact_path), "--json"])

    assert code == 1
    doc = json.loads(capsys.readouterr().out)
    names = [gate["name"] for gate in doc["gates"]]
    assert "chaos/adversarial validation" in names
    adversarial = next(g for g in doc["gates"] if g["name"] == "chaos/adversarial validation")
    assert adversarial["status"] == "FAIL"


def test_main_passes_the_adversarial_gate_on_a_real_pass_artifact(tmp_path, capsys):
    artifact_path = tmp_path / "adversarial.json"
    artifact_path.write_text(json.dumps({
        "status": "pass", "duration_sec": 5.0,
        "threat_model_matrix": "docs/design/threat-model-matrix-2026-09-06.md",
    }))

    main(["--adversarial-artifact", str(artifact_path), "--json"])

    doc = json.loads(capsys.readouterr().out)
    adversarial = next(g for g in doc["gates"] if g["name"] == "chaos/adversarial validation")
    assert adversarial["status"] == "PASS"
