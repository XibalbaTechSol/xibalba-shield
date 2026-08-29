from __future__ import annotations

import subprocess

from scripts import e2e_validate


def _result(returncode: int, output: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=output)


def test_live_bcc_gate_does_not_promote_an_all_skipped_run_to_pass(monkeypatch):
    monkeypatch.setattr(
        e2e_validate,
        "_run",
        lambda *args, **kwargs: _result(0, "1 skipped in 0.10s\n"),
    )
    report = e2e_validate.Report()

    e2e_validate.check_live_bcc(report, "http://127.0.0.1:9")

    assert [(check.name, check.status) for check in report.checks] == [
        ("live bcc exporter", "SKIP")
    ]


def test_live_bcc_gate_reports_a_real_pass(monkeypatch):
    monkeypatch.setattr(
        e2e_validate,
        "_run",
        lambda *args, **kwargs: _result(0, "1 passed in 0.20s\n"),
    )
    report = e2e_validate.Report()

    e2e_validate.check_live_bcc(report, "http://localhost:8000")

    assert report.checks[0].status == "PASS"


def test_live_bcc_gate_reports_test_failure(monkeypatch):
    monkeypatch.setattr(
        e2e_validate,
        "_run",
        lambda *args, **kwargs: _result(1, "connection failed\n"),
    )
    report = e2e_validate.Report()

    e2e_validate.check_live_bcc(report, "http://localhost:8000")

    assert report.checks[0].status == "FAIL"
    assert report.checks[0].detail == "connection failed"
