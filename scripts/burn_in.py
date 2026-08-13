#!/usr/bin/env python3
"""
Root-free burn-in harness for Shield's enforcement/export loop.

This uses the dev sensor by default so it can run in CI and on laptops. For customer pilots,
run it beside the Linux eBPF service and SIEM/Integrity exporters, then compare this local
resource/export baseline with host telemetry over multi-day windows.
"""

from __future__ import annotations

import argparse
import json
import resource
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from shield.agent_core.eventlog import EventLog
from shield.agent_core.registry import AgentRegistry, DeviceContext
from shield.agent_core.router import EventRouter
from shield.config import load_policy_bundle
from shield.policy_engine import PolicyEngine
from shield.sensors.dev_generator import DevModeSensor


class _NullExporter:
    def export_event(self, _event):
        return None

    def export_decision(self, _decision):
        return {"authorized": True, "reason": "burn-in local null exporter"}


def _load_false_positive_stats(path: Path | None) -> dict[str, object]:
    if path is None:
        return {
            "rate": None,
            "reviewed": 0,
            "false_positive_count": 0,
            "note": "requires operator-labeled pilot review data; this harness records candidate decision volume only",
        }
    reviewed = 0
    false_positive_count = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if "false_positive" not in row:
            continue
        reviewed += 1
        false_positive_count += int(bool(row["false_positive"]))
    return {
        "rate": round(false_positive_count / reviewed, 6) if reviewed else None,
        "reviewed": reviewed,
        "false_positive_count": false_positive_count,
        "note": "operator-labeled review file supplied" if reviewed else "no false_positive labels found in review file",
    }


def _load_detection_quality_stats(path: Path | None) -> dict[str, object]:
    if path is None:
        return {
            "schema": "shield.detection_quality.v1",
            "sample_count": 0,
            "shield_adr": None,
            "precision": None,
            "blocking_false_positive_rate": None,
            "mean_time_to_contain_sec": None,
            "evidence_export_success": None,
            "note": "requires labeled pilot, benchmark, red-team, or synthetic fixture data",
        }
    samples = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        row = json.loads(line)
        try:
            samples.append(_normalize_detection_quality_sample(row))
        except ValueError as exc:
            raise ValueError(f"{path}:{line_number}: {exc}") from exc
    aggregate = _detection_quality_aggregate(samples)
    aggregate["schema"] = "shield.detection_quality.v1"
    aggregate["note"] = "labeled detection-quality file supplied" if samples else "no samples found in detection-quality file"
    return aggregate


def _normalize_detection_quality_sample(row: dict[str, object]) -> dict[str, object]:
    event_id = str(row.get("event_id", "")).strip()
    label = str(row.get("label", "")).strip().lower()
    label_source = str(row.get("label_source", "")).strip()
    action = str(row.get("decision_action", row.get("action", ""))).strip().lower()
    if not event_id:
        raise ValueError("sample missing event_id")
    if label not in {"malicious", "benign", "ambiguous", "synthetic"}:
        raise ValueError(f"sample {event_id} has invalid label {label!r}")
    if not label_source:
        raise ValueError(f"sample {event_id} missing label_source")
    if not action:
        raise ValueError(f"sample {event_id} missing decision_action")
    return {
        "event_id": event_id,
        "label": label,
        "label_source": label_source,
        "decision_action": action,
        "first_observed_timestamp": row.get("first_observed_timestamp"),
        "containment_timestamp": row.get("containment_timestamp"),
        "export_attempted": bool(row.get("export_attempted", row.get("exported", False))),
        "export_success": bool(row.get("export_success", row.get("decision_exported", False))),
    }


def _detection_quality_aggregate(samples: list[dict[str, object]]) -> dict[str, object]:
    malicious = [sample for sample in samples if sample["label"] == "malicious"]
    benign = [sample for sample in samples if sample["label"] == "benign"]
    true_positive = [sample for sample in malicious if sample["decision_action"] in {"deny", "contain", "escalate"}]
    security_decisions = [sample for sample in samples if sample["decision_action"] in {"deny", "contain", "escalate"}]
    blocking_false_positive = [sample for sample in benign if sample["decision_action"] in {"deny", "contain"}]
    export_attempted = [sample for sample in samples if sample["export_attempted"]]
    export_success = [sample for sample in export_attempted if sample["export_success"]]
    contain_latencies = [
        latency
        for sample in true_positive
        if sample["decision_action"] == "contain"
        for latency in [_seconds_between(sample.get("first_observed_timestamp"), sample.get("containment_timestamp"))]
        if latency is not None
    ]
    return {
        "sample_count": len(samples),
        "labeled_malicious_events": len(malicious),
        "true_positive_security_decisions": len(true_positive),
        "shield_adr": _rate(len(true_positive), len(malicious)),
        "labeled_benign_events": len(benign),
        "benign_events_blocked_or_contained": len(blocking_false_positive),
        "blocking_false_positive_rate": _rate(len(blocking_false_positive), len(benign)),
        "all_deny_contain_escalate_decisions": len(security_decisions),
        "precision": _rate(len(true_positive), len(security_decisions)),
        "mean_time_to_contain_sec": round(sum(contain_latencies) / len(contain_latencies), 6) if contain_latencies else None,
        "export_attempted_decisions": len(export_attempted),
        "successful_exports": len(export_success),
        "evidence_export_success": _rate(len(export_success), len(export_attempted)),
    }


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _seconds_between(start: object, end: object) -> float | None:
    if not start or not end:
        return None
    start_dt = _parse_timestamp(str(start))
    end_dt = _parse_timestamp(str(end))
    return max(0.0, (end_dt - start_dt).total_seconds())


def _parse_timestamp(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(prog="burn_in.py")
    parser.add_argument("--duration-sec", type=float, default=60.0)
    parser.add_argument("--max-events", type=int, default=1000)
    parser.add_argument("--rules", type=Path, default=Path("policies/defaults/smb.json"))
    parser.add_argument("--output", type=Path, default=Path("artifacts/burn-in.json"))
    parser.add_argument("--log-path", type=Path, default=Path("artifacts/burn-in-decisions.jsonl"))
    parser.add_argument(
        "--false-positive-labels",
        type=Path,
        default=None,
        help="optional JSONL operator review file with false_positive booleans",
    )
    parser.add_argument(
        "--detection-quality-labels",
        type=Path,
        default=None,
        help="optional JSONL labeled-event file for Shield ADR, precision, and time-to-contain",
    )
    args = parser.parse_args()

    bundle = load_policy_bundle(args.rules)
    router = EventRouter(
        device=DeviceContext(device_id="burn-in-dev", tenant_id="burn-in", device_role="workstation"),
        registry=AgentRegistry(),
        policy_engine=PolicyEngine(rules=bundle.rules, policy_version=bundle.version, policy_hash=bundle.hash),
        exporter=_NullExporter(),
        event_log=EventLog(args.log_path),
    )
    sensor = DevModeSensor(device_id="burn-in-dev", interval_sec=0)
    started = time.monotonic()
    decisions: dict[str, int] = {}
    processed = 0
    for event in sensor.events():
        decision = router.handle(event)
        decisions[decision.decision.action] = decisions.get(decision.decision.action, 0) + 1
        processed += 1
        if processed >= args.max_events or time.monotonic() - started >= args.duration_sec:
            break

    elapsed = time.monotonic() - started
    usage = resource.getrusage(resource.RUSAGE_SELF)
    false_positive_stats = _load_false_positive_stats(args.false_positive_labels)
    try:
        detection_quality = _load_detection_quality_stats(args.detection_quality_labels)
    except ValueError as exc:
        print(f"burn_in.py: {exc}", file=sys.stderr)
        return 2
    report = {
        "duration_sec": round(elapsed, 3),
        "events": processed,
        "events_per_sec": round(processed / elapsed, 2) if elapsed else processed,
        "decisions": decisions,
        "max_rss_kb": usage.ru_maxrss,
        "policy_hash": bundle.hash,
        "policy_version": bundle.version,
        "false_positive_rate": false_positive_stats["rate"],
        "false_positive_reviewed": false_positive_stats["reviewed"],
        "false_positive_count": false_positive_stats["false_positive_count"],
        "false_positive_note": false_positive_stats["note"],
        "detection_quality": detection_quality,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
