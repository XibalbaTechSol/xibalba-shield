"""Bounded, metadata-only endpoint inventory for posture and control-plane reporting."""
from __future__ import annotations

import os
import platform
import hashlib
import json
import subprocess
from typing import Any

import psutil


def collect_inventory(*, max_processes: int = 256, max_packages: int = 512) -> dict[str, Any]:
    """Collect bounded endpoint metadata; never reads file contents or process cmdlines."""
    if max_processes < 1 or max_packages < 1:
        raise ValueError("inventory limits must be positive")
    processes = []
    for proc in psutil.process_iter(["pid", "name", "username", "status"]):
        if len(processes) >= max_processes:
            break
        try:
            info = proc.info
            processes.append({k: info.get(k) for k in ("pid", "name", "username", "status")})
        except (psutil.Error, OSError):
            continue
    packages: list[dict[str, str]] = []
    if platform.system() in {"Linux", "Darwin"}:
        commands = {
            "Linux": [["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
                      ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"]],
            "Darwin": [["brew", "list", "--versions"]],
        }[platform.system()]
        for command in commands:
          try:
            raw = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
            if raw.returncode != 0:
                continue
            for line in raw.stdout.splitlines()[:max_packages]:
                fields = line.split()
                name, version = (fields[0], fields[1]) if len(fields) >= 2 else line.partition("\t")[::2]
                if name and version:
                    packages.append({"name": name[:128], "version": version[:256]})
            if packages:
                break
          except (OSError, subprocess.SubprocessError):
            continue
    snapshot = {
        "schema": "xibalba.shield.inventory.v1",
        "os": {"system": platform.system(), "release": platform.release()[:128], "machine": platform.machine()[:64]},
        "hardware": {"cpu_count": os.cpu_count() or 0, "memory_bytes": psutil.virtual_memory().total},
        "posture": _posture(),
        "processes": processes,
        "packages": packages,
        "vulnerability": {"status": "unavailable", "advisory_source": None,
                           "packages_in_scope": len(packages), "known_findings": None,
                           "reason": "no trusted advisory database configured"},
        "limits": {"max_processes": max_processes, "max_packages": max_packages},
    }
    snapshot["snapshot_hash"] = hashlib.sha256(
        json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return snapshot


def _posture() -> dict[str, str]:
    """Read only coarse host posture; unavailable evidence remains explicitly unknown."""
    posture = {"secure_boot": "unknown", "disk_encryption": "unknown", "tpm": "unknown"}
    if platform.system() != "Linux":
        return posture
    secure_boot = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    if os.path.exists(secure_boot):
        try:
            data = open(secure_boot, "rb").read()
            posture["secure_boot"] = "enabled" if data[-1:] == b"\x01" else "disabled"
        except OSError:
            pass
    try:
        result = subprocess.run(["lsblk", "-o", "TYPE", "-n"], capture_output=True, text=True, timeout=3, check=False)
        if result.returncode == 0:
            posture["disk_encryption"] = "enabled" if "crypt" in result.stdout.split() else "disabled"
    except (OSError, subprocess.SubprocessError):
        pass
    posture["tpm"] = "enabled" if os.path.exists("/dev/tpm0") else "disabled"
    return posture


def inventory_drift(previous: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, Any]:
    """Compare canonical inventory hashes without diffing or exposing raw values."""
    current_hash = current.get("snapshot_hash")
    previous_hash = previous.get("snapshot_hash") if previous else None
    return {
        "changed": bool(previous_hash and current_hash and previous_hash != current_hash),
        "previous_hash": previous_hash,
        "current_hash": current_hash,
        "comparable": bool(previous_hash and current_hash),
    }


def vulnerability_readiness(inventory: dict[str, Any], *, advisory_source: str | None = None) -> dict[str, Any]:
    """Return honest vulnerability posture; absence of an advisory source is not a clean result."""
    packages = inventory.get("packages", [])
    return {
        "status": "unavailable" if not advisory_source else "source_configured",
        "advisory_source": advisory_source,
        "packages_in_scope": len(packages) if isinstance(packages, list) else 0,
        "known_findings": None,
        "reason": "no trusted advisory database configured" if not advisory_source else "advisory matching pending",
    }
