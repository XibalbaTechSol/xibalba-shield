"""Versioned release directory + atomic symlink swap -- closes the "rollback is a
manual reinstall" half of `docs/PRODUCTION_READINESS_PLAN.md` §7 item 5. Mirrors the
standard releases/<version> + `current` symlink pattern (Capistrano and similar
deployment tools use the same shape): install unpacks a NEW, independent release
directory and only swaps `current` after the install inside it succeeds, so a failed
install never touches a working deployment, and rollback to an already-installed
version is a symlink flip plus a service restart -- no reinstall, no network, no
re-verification -- not `docs/runbooks/linux-agent.md`'s previous "reinstall the
previous reviewed wheel or commit" manual procedure.

The systemd unit's `ExecStart` would need to point at `<current_link>/bin/shield` for
this to be the live install path in production -- that unit-file change is a separate,
deliberate decision (it changes the real deployment path for every existing install) and
is NOT made in this commit; this module is the mechanism, ready to be wired in.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .signing import VerificationResult, verify_artifact

Installer = Callable[[Path, Path], None]


class ReleaseError(RuntimeError):
    pass


@dataclass(frozen=True)
class InstallResult:
    version: str
    release_dir: Path
    previous_version: str | None
    verification: VerificationResult


def _read_current_version(current_link: Path) -> str | None:
    if not current_link.is_symlink():
        return None
    try:
        return current_link.resolve().name
    except OSError:
        return None


def _atomic_symlink_swap(current_link: Path, target_dir: Path) -> None:
    """Symlink to a temp name, then `os.rename` over the real name -- `os.rename` on the
    same filesystem is atomic, so there is never a window where `current_link` points at
    nothing or a half-written target, even if the process is killed mid-swap."""
    tmp_link = current_link.with_name(current_link.name + ".tmp")
    if tmp_link.exists() or tmp_link.is_symlink():
        tmp_link.unlink()
    tmp_link.symlink_to(target_dir, target_is_directory=True)
    os.rename(tmp_link, current_link)


def default_installer(*, python_bin: str | None = None) -> Installer:
    """The real installer: a fresh venv per release, then `pip install` the verified
    wheel into it -- both real, standard, independently-tested tools (not reimplemented
    here). Unit tests inject a fake `Installer` instead of running this for real every
    time (a real venv+pip install takes real seconds); one dedicated integration test
    exercises this default against a real trivial wheel."""

    def _install(wheel_path: Path, venv_dir: Path) -> None:
        subprocess.run(
            [python_bin or sys.executable, "-m", "venv", str(venv_dir)],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            [str(venv_dir / "bin" / "pip"), "install", "--quiet", str(wheel_path)],
            check=True, capture_output=True, text=True,
        )

    return _install


def install_release(
    *,
    wheel_path: Path,
    attestation_path: Path,
    version: str,
    releases_dir: Path,
    current_link: Path,
    trusted_keys: list[str] | None = None,
    installer: Installer | None = None,
) -> InstallResult:
    """Verifies the wheel's signed attestation BEFORE touching disk for the new release
    -- an unverified/tampered artifact never gets a release directory at all, let alone
    a chance at `current`. On any installer failure, the partial release directory is
    removed so a failed install leaves no half-installed version to accidentally roll
    back to."""
    attestation = json.loads(attestation_path.read_text())
    verification = verify_artifact(wheel_path, attestation, trusted_keys)
    if not verification.verified:
        raise ReleaseError(f"refusing to install unverified artifact: {verification.reason}")

    releases_dir.mkdir(parents=True, exist_ok=True)
    release_dir = releases_dir / version
    if release_dir.exists():
        raise ReleaseError(f"release {version} already exists at {release_dir}")

    previous_version = _read_current_version(current_link)
    install_fn = installer or default_installer()

    release_dir.mkdir(parents=True)
    try:
        install_fn(wheel_path, release_dir / "venv")
    except Exception as exc:  # noqa: BLE001 -- a failed install must not leave debris
        shutil.rmtree(release_dir, ignore_errors=True)
        raise ReleaseError(f"install failed, release directory removed: {exc}") from exc

    (release_dir / "attestation.json").write_text(json.dumps(attestation, indent=2, sort_keys=True))
    _atomic_symlink_swap(current_link, release_dir)

    return InstallResult(
        version=version, release_dir=release_dir,
        previous_version=previous_version, verification=verification,
    )


def rollback(*, version: str, releases_dir: Path, current_link: Path) -> str:
    """Flip `current` back to an already-installed release. Deliberately does NOT
    re-verify the signature or reinstall -- the release was verified once, at install
    time, and its files haven't changed since (this is a local filesystem operation, not
    a network fetch of anything new)."""
    target = releases_dir / version
    if not target.is_dir():
        raise ReleaseError(f"release {version} is not installed at {target}")
    _atomic_symlink_swap(current_link, target)
    return version


def list_releases(*, releases_dir: Path, current_link: Path) -> list[dict[str, object]]:
    current_version = _read_current_version(current_link)
    if not releases_dir.is_dir():
        return []
    return [
        {"version": entry.name, "current": entry.name == current_version}
        for entry in sorted(releases_dir.iterdir())
        if entry.is_dir()
    ]
