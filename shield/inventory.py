"""Bounded, metadata-only endpoint inventory for posture and control-plane reporting."""
from __future__ import annotations

import os
import platform
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
    if platform.system() == "Linux":
        try:
            raw = subprocess.run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
                                 capture_output=True, text=True, timeout=5, check=False)
            for line in raw.stdout.splitlines()[:max_packages]:
                name, _, version = line.partition("\t")
                if name and version:
                    packages.append({"name": name[:128], "version": version[:256]})
        except (OSError, subprocess.SubprocessError):
            pass
    return {
        "schema": "xibalba.shield.inventory.v1",
        "os": {"system": platform.system(), "release": platform.release()[:128], "machine": platform.machine()[:64]},
        "hardware": {"cpu_count": os.cpu_count() or 0, "memory_bytes": psutil.virtual_memory().total},
        "posture": {"secure_boot": "unknown", "disk_encryption": "unknown", "tpm": "unknown"},
        "processes": processes,
        "packages": packages,
        "limits": {"max_processes": max_processes, "max_packages": max_packages},
    }
