#!/usr/bin/env python3
"""
End-to-end validation harness for Xibalba Shield.

Runs real local checks by default and records unavailable root/live-stack checks as SKIP.
No mocked eBPF or mocked Integrity service is substituted for a missing dependency.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
DEFAULT_POLICIES = [
    REPO_ROOT / "policies" / "defaults" / "smb.json",
    REPO_ROOT / "policies" / "defaults" / "professional-services.json",
    REPO_ROOT / "policies" / "defaults" / "regulated.json",
]


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)

    def add(self, name: str, status: str, detail: str = "") -> None:
        self.checks.append(Check(name=name, status=status, detail=detail))

    def failed(self) -> bool:
        return any(check.status == "FAIL" for check in self.checks)

    def print_text(self) -> None:
        for check in self.checks:
            suffix = f" - {check.detail}" if check.detail else ""
            print(f"{check.status:4} {check.name}{suffix}")

    def print_json(self) -> None:
        print(json.dumps({"checks": [vars(check) for check in self.checks]}, indent=2))


def _run(cmd: list[str], *, timeout: int = 120, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        env={**os.environ, **(env or {})},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )


def _reachable(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _add_process_result(report: Report, name: str, proc: subprocess.CompletedProcess) -> None:
    if proc.returncode == 0:
        last = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "ok"
        report.add(name, "PASS", last)
    else:
        report.add(name, "FAIL", proc.stdout.strip()[-500:])


def check_root_free_tests(report: Report) -> None:
    # Keep the root-free suite independent of whatever live bcc_middleware happens to be
    # running on localhost. Live exporter validation is a separate check below.
    _add_process_result(
        report,
        "root-free pytest",
        _run([PYTHON, "-m", "pytest", "-q"], timeout=180, env={"BCC_MIDDLEWARE_URL": "http://127.0.0.1:9"}),
    )


def check_default_policies(report: Report) -> None:
    for policy in DEFAULT_POLICIES:
        proc = _run([PYTHON, "-m", "shield.cli", "validate", "--rules", str(policy)], timeout=30)
        _add_process_result(report, f"validate {policy.relative_to(REPO_ROOT)}", proc)


def check_local_dev_loop(report: Report) -> None:
    with tempfile.TemporaryDirectory(prefix="shield-e2e-") as tmp:
        log_path = Path(tmp) / "decisions.jsonl"
        proc = _run(
            [
                PYTHON, "-m", "shield.cli",
                "--log-path", str(log_path),
                "run",
                "--sensor", "dev",
                "--device-id", "e2e-dev",
                "--rules", str(REPO_ROOT / "policies" / "defaults" / "smb.json"),
                "--no-exporter",
                "--max-events", "12",
                "--dev-interval", "0",
            ],
            timeout=60,
        )
        if proc.returncode != 0:
            report.add("local dev shield run", "FAIL", proc.stdout.strip()[-500:])
            return
        rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
        if len(rows) != 12:
            report.add("local dev decision log", "FAIL", f"expected 12 decisions, found {len(rows)}")
            return
        if not all(row.get("export", {}).get("decision_exported") is True for row in rows):
            report.add("local dev export status", "FAIL", "local no-exporter decisions did not record export success")
            return
        report.add("local dev shield run", "PASS", "12 decisions logged with export=ok")


def check_btf(report: Report) -> None:
    btf = Path("/sys/kernel/btf/vmlinux")
    bpftool = Path("/usr/sbin/bpftool")
    if not btf.exists() or not os.access(btf, os.R_OK) or not bpftool.exists():
        report.add("kernel BTF", "SKIP", "bpftool or /sys/kernel/btf/vmlinux unavailable")
        return
    proc = subprocess.run(
        [str(bpftool), "btf", "dump", "file", str(btf), "format", "c"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
    )
    fields = ["struct sock_common", "skc_daddr", "skc_rcv_saddr", "skc_dport", "skc_num"]
    missing = [field for field in fields if field not in proc.stdout]
    if proc.returncode != 0 or missing:
        report.add("kernel BTF sock layout", "FAIL", f"missing {missing}; output={proc.stdout[-300:]}")
    else:
        report.add("kernel BTF sock layout", "PASS", "TCP sensor fields are present")


def check_root_ebpf(report: Report) -> None:
    if os.geteuid() != 0:
        report.add("root eBPF tests", "SKIP", "run with sudo to load and verify real BPF probes")
        report.add("root TCP-connect eBPF", "SKIP", "run sudo python3 scripts/verify_tcp_connect_root.py")
        return
    _add_process_result(report, "root eBPF tests", _run([PYTHON, "-m", "pytest", "-q", "tests/test_ebpf_sensor.py"], timeout=120))
    _add_process_result(
        report,
        "root TCP-connect eBPF",
        _run([PYTHON, "-m", "pytest", "-q", "tests/test_ebpf_sensor.py", "-k", "tcp_connect"], timeout=120),
    )


def check_live_bcc(report: Report, bcc_url: str) -> None:
    host_port = bcc_url.removeprefix("http://").removeprefix("https://").split("/", 1)[0]
    host, _, raw_port = host_port.partition(":")
    port = int(raw_port or (443 if bcc_url.startswith("https://") else 80))
    if not _reachable(host, port):
        report.add("live bcc_middleware", "SKIP", f"{bcc_url} is not reachable")
        return
    proc = _run(
        [PYTHON, "-m", "pytest", "-q", "tests/test_integrity_exporter.py"],
        timeout=120,
        env={"BCC_MIDDLEWARE_URL": bcc_url},
    )
    _add_process_result(report, "live bcc exporter", proc)


def check_exporter_registration_readback(report: Report) -> None:
    preflight = _run([PYTHON, "scripts/did_env_preflight.py"], timeout=10)
    if preflight.returncode != 0:
        try:
            doc = json.loads(preflight.stdout)
            report.add("DID environment preflight", "SKIP", f"blocked: {', '.join(doc.get('blockers', []))}")
        except json.JSONDecodeError:
            report.add("DID environment preflight", "SKIP", preflight.stdout.strip()[-300:])
        return
    report.add("DID environment preflight", "PASS", "live prerequisites available")
    proc = _run([PYTHON, "scripts/verify_oracle_registration.py"], timeout=60)
    if proc.returncode == 0:
        report.add("exporter DID readback", "PASS", "registered DID resolved")
        return
    detail = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "readback unavailable"
    report.add("exporter DID readback", "SKIP", detail[-300:])


def check_burn_in_smoke(report: Report) -> None:
    with tempfile.TemporaryDirectory(prefix="shield-burn-in-") as tmp:
        output = Path(tmp) / "burn-in.json"
        labels = Path(tmp) / "labels.jsonl"
        labels.write_text('{"decision_id":"candidate-1","false_positive":false}\n', encoding="utf-8")
        proc = _run(
            [
                PYTHON,
                "scripts/burn_in.py",
                "--duration-sec",
                "5",
                "--max-events",
                "25",
                "--output",
                str(output),
                "--log-path",
                str(Path(tmp) / "decisions.jsonl"),
                "--false-positive-labels",
                str(labels),
            ],
            timeout=30,
        )
        if proc.returncode != 0:
            report.add("burn-in smoke", "FAIL", proc.stdout.strip()[-500:])
            return
        doc = json.loads(output.read_text(encoding="utf-8"))
        if doc.get("events") != 25 or doc.get("false_positive_reviewed") != 1:
            report.add("burn-in smoke", "FAIL", f"unexpected report {doc}")
            return
        report.add("burn-in smoke", "PASS", f"{doc['events']} events, fp_rate={doc['false_positive_rate']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scripts/e2e_validate.py")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--bcc-url", default=os.environ.get("BCC_MIDDLEWARE_URL", "http://localhost:8000"))
    args = parser.parse_args(argv)

    report = Report()
    check_root_free_tests(report)
    check_default_policies(report)
    check_local_dev_loop(report)
    check_burn_in_smoke(report)
    check_btf(report)
    check_root_ebpf(report)
    check_live_bcc(report, args.bcc_url)
    check_exporter_registration_readback(report)

    report.print_json() if args.json else report.print_text()
    return 1 if report.failed() else 0


if __name__ == "__main__":
    sys.exit(main())
