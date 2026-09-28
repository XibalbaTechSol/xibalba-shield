"""Every non-Python runtime file under shield/ must ship in the built package.

Regression: the Hermes contract schemas were loaded via Path(__file__) but not listed in
package-data, so the deployed sensor could not import shield.hermes_contract (C5 install).
"""

from __future__ import annotations

import fnmatch
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC_SUFFIXES = {".md"}


def test_package_data_covers_every_tracked_runtime_file():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    globs = config["tool"]["setuptools"]["package-data"]["shield"]
    tracked = subprocess.run(["git", "ls-files", "shield"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
    runtime_files = [f[len("shield/"):] for f in tracked if not f.endswith(".py") and Path(f).suffix not in DOC_SUFFIXES]
    missing = [f for f in runtime_files if not any(fnmatch.fnmatch(f, pattern) for pattern in globs)]
    assert missing == [], f"add these to [tool.setuptools.package-data]: {missing}"
