"""
SIEM/SOAR export adapters.

The JSONL path is for filebeat/fluent-bit/Splunk UF collection. The webhook path is a generic
SOAR receiver contract: one JSON decision row per POST, no batching or proprietary schema.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SiemExportResult:
    exported: int
    failed: int = 0


def export_decision_log_to_jsonl(source: Path | str, destination: Path | str, *, profile: str = "generic") -> SiemExportResult:
    src = Path(source)
    dst = Path(destination)
    dst.parent.mkdir(parents=True, exist_ok=True)
    exported = 0
    with src.open("r", encoding="utf-8") as inp, dst.open("w", encoding="utf-8") as out:
        for line in inp:
            row = json.loads(line)
            _apply_profile(row, profile)
            out.write(json.dumps(row, sort_keys=True) + "\n")
            exported += 1
    return SiemExportResult(exported=exported)


def _apply_profile(row: dict, profile: str) -> None:
    action = row.get("decision", {}).get("action")
    row["event.module"] = "xibalba-shield"
    row["event.kind"] = "alert" if action in {"deny", "contain", "escalate"} else "event"
    if profile == "generic":
        return
    if profile == "elastic":
        row["ecs.version"] = "8.0.0"
        row["event.dataset"] = "xibalba_shield.decision"
        row["rule.id"] = row.get("rule", {}).get("rule_id", "")
        return
    if profile == "splunk":
        row["source"] = "xibalba:shield:decision"
        row["sourcetype"] = "xibalba_shield_decision"
        row["severity"] = row.get("decision", {}).get("severity", "")
        return
    raise ValueError(f"unknown SIEM profile {profile!r}")


def post_decision_log_to_webhook(source: Path | str, webhook_url: str, *, timeout_sec: float = 10.0) -> SiemExportResult:
    exported = 0
    failed = 0
    with Path(source).open("r", encoding="utf-8") as inp:
        for line in inp:
            row = json.loads(line)
            body = json.dumps(row).encode("utf-8")
            request = urllib.request.Request(
                webhook_url,
                data=body,
                method="POST",
                headers={"Content-Type": "application/json", "User-Agent": "xibalba-shield/siem"},
            )
            try:
                with urllib.request.urlopen(request, timeout=timeout_sec) as response:
                    status = getattr(response, "status", 200)
                    if status < 200 or status >= 300:
                        failed += 1
                    else:
                        exported += 1
            except urllib.error.URLError:
                failed += 1
    return SiemExportResult(exported=exported, failed=failed)
