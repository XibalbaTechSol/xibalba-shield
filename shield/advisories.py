"""Deterministic local advisory matching with explicit freshness and provenance."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any


def load_advisories(path: Path, *, max_age_seconds: int = 86400) -> dict[str, Any]:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    doc = json.loads(raw)
    if not isinstance(doc, dict) or not isinstance(doc.get("advisories"), list):
        raise ValueError("advisory source must contain an advisories array")
    updated = float(doc.get("updated_at", 0))
    if updated <= 0 or time.time() - updated > max_age_seconds:
        raise ValueError("advisory source is stale")
    return {"source_hash": digest, "updated_at": updated, "advisories": doc["advisories"]}


def match_advisories(inventory: dict[str, Any], source: dict[str, Any], *, max_findings: int = 256) -> dict[str, Any]:
    if max_findings < 1:
        raise ValueError("max_findings must be positive")
    packages = {(p.get("name"), p.get("version")) for p in inventory.get("packages", []) if isinstance(p, dict)}
    findings = []
    for advisory in source.get("advisories", []):
        if not isinstance(advisory, dict):
            continue
        if (advisory.get("package"), advisory.get("version")) in packages:
            finding = {k: advisory.get(k) for k in ("id", "package", "version", "severity", "summary", "fixed_version")}
            finding["priority"] = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(finding.get("severity")).lower(), 0)
            findings.append(finding)
            if len(findings) >= max_findings:
                break
    findings.sort(key=lambda item: item["priority"], reverse=True)
    return {"status": "matched", "source_hash": source.get("source_hash"),
            "updated_at": source.get("updated_at"), "known_findings": findings}


def build_remediation_plan(findings: list[dict[str, Any]], *, maintenance_window: str | None = None) -> dict[str, Any]:
    """Build approval-required remediation intent; this function never executes a package change."""
    actions = []
    for finding in findings[:256]:
        fixed = finding.get("fixed_version")
        if not fixed:
            continue
        actions.append({"package": finding.get("package"), "from_version": finding.get("version"),
                        "to_version": fixed, "advisory_id": finding.get("id"),
                        "priority": finding.get("priority", 0), "requires_approval": True})
    return {"status": "approval_required", "maintenance_window": maintenance_window,
            "actions": sorted(actions, key=lambda item: item["priority"], reverse=True),
            "executed": False}
