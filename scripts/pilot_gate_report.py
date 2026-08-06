#!/usr/bin/env python3
"""Summarize Shield's external pilot gates from real verification artifacts."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Gate:
    name: str
    status: str
    detail: str


def _load_json(path: Path | None) -> dict | None:
    if path is None:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"status": "blocked", "reason": f"artifact not found: {path}"}
    except json.JSONDecodeError as exc:
        return {"status": "fail", "reason": f"invalid JSON artifact {path}: {exc}"}


def _gate_from_status(name: str, artifact: dict | None, *, pass_values: set[str] | None = None) -> Gate:
    if artifact is None:
        return Gate(name, "BLOCKED", "no real artifact supplied")
    status = str(artifact.get("status", "")).lower()
    pass_values = pass_values or {"pass", "passed", "ok", "ready"}
    if status in pass_values:
        return Gate(name, "PASS", artifact.get("reason") or artifact.get("detail") or "artifact reports pass")
    if status in {"blocked", "skip", "skipped"}:
        return Gate(name, "BLOCKED", artifact.get("reason") or ", ".join(artifact.get("blockers", [])) or "artifact reports blocked")
    return Gate(name, "FAIL", artifact.get("reason") or artifact.get("detail") or f"artifact status={status or 'missing'}")


def _burn_in_gate(artifact: dict | None, min_hours: float) -> Gate:
    if artifact is None:
        return Gate("multi-day burn-in", "BLOCKED", "no burn-in artifact supplied")
    duration = float(artifact.get("duration_sec", 0)) / 3600
    reviewed = int(artifact.get("false_positive_reviewed", 0))
    fp_rate = artifact.get("false_positive_rate")
    if duration < min_hours:
        return Gate("multi-day burn-in", "BLOCKED", f"only {duration:.2f}h recorded; need >= {min_hours:.2f}h")
    if reviewed == 0 or fp_rate is None:
        return Gate("multi-day burn-in", "BLOCKED", "operator false-positive review labels are missing")
    if float(fp_rate) > 0.05:
        return Gate("multi-day burn-in", "FAIL", f"false-positive rate {fp_rate} exceeds 0.05")
    return Gate("multi-day burn-in", "PASS", f"{duration:.2f}h recorded; false-positive rate {fp_rate}")


def _hardening_gate(path: Path | None) -> Gate:
    if path is None:
        return Gate("root/admin resistance hardening", "BLOCKED", "no OS hardening attestation supplied")
    text = path.read_text(encoding="utf-8")
    required = ("secure_boot", "tpm_or_mdm", "service_protection", "log_key_protection")
    missing = [key for key in required if key not in text]
    if missing:
        return Gate("root/admin resistance hardening", "BLOCKED", f"attestation missing fields: {', '.join(missing)}")
    return Gate("root/admin resistance hardening", "PASS", f"attestation supplied: {path}")


def _installer_gate(path: Path | None) -> Gate:
    if path is None:
        return Gate("installer/updater signing", "BLOCKED", "no signing/release attestation supplied")
    text = path.read_text(encoding="utf-8")
    required = ("artifact_sha256", "signature", "service_manager", "rollback")
    missing = [key for key in required if key not in text]
    if missing:
        return Gate("installer/updater signing", "BLOCKED", f"attestation missing fields: {', '.join(missing)}")
    return Gate("installer/updater signing", "PASS", f"attestation supplied: {path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scripts/pilot_gate_report.py")
    parser.add_argument("--tcp-artifact", type=Path, help="JSON from scripts/verify_tcp_connect_root.py")
    parser.add_argument("--did-artifact", type=Path, help="JSON from scripts/verify_oracle_registration.py")
    parser.add_argument("--windows-artifact", type=Path, help="JSON from Windows native sensor validation")
    parser.add_argument("--macos-artifact", type=Path, help="JSON from macOS native sensor validation")
    parser.add_argument("--burn-in-artifact", type=Path, help="JSON from scripts/burn_in.py")
    parser.add_argument("--min-burn-in-hours", type=float, default=48.0)
    parser.add_argument("--hardening-attestation", type=Path, help="text/JSON attestation for OS-level hardening")
    parser.add_argument("--installer-attestation", type=Path, help="text/JSON attestation for signed package/update")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    gates = [
        _gate_from_status("TCP-connect eBPF target-kernel verification", _load_json(args.tcp_artifact)),
        _gate_from_status("live DID oracle readback", _load_json(args.did_artifact), pass_values={"pass", "passed", "ok"}),
        _gate_from_status("Windows native sensors", _load_json(args.windows_artifact)),
        _gate_from_status("macOS native sensors", _load_json(args.macos_artifact)),
        _hardening_gate(args.hardening_attestation),
        _installer_gate(args.installer_attestation),
        _burn_in_gate(_load_json(args.burn_in_artifact), args.min_burn_in_hours),
    ]
    doc = {"gates": [gate.__dict__ for gate in gates]}
    if args.json:
        print(json.dumps(doc, indent=2, sort_keys=True))
    else:
        for gate in gates:
            print(f"{gate.status:7} {gate.name} - {gate.detail}")
    return 1 if any(gate.status == "FAIL" for gate in gates) else 0


if __name__ == "__main__":
    raise SystemExit(main())
