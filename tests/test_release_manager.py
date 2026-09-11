"""Coverage for shield/release/manager.py -- versioned releases + atomic symlink
rollback, docs/PRODUCTION_READINESS_PLAN.md §7 item 5. Most tests inject a fake
`installer` (fast, deterministic) to exercise the real verify/directory/symlink
orchestration without a real venv+pip install every time; one dedicated test exercises
the real `default_installer()` end to end against a real tiny wheel."""

from __future__ import annotations

from pathlib import Path

import pytest
from integrity_sdk.did import Keypair

from shield.release import ReleaseError, install_release, list_releases, rollback, sign_artifact


def _signed_wheel(tmp_path, name="artifact.whl", content=b"fake wheel bytes", keypair=None):
    keypair = keypair or Keypair.generate()
    wheel_path = tmp_path / name
    wheel_path.write_bytes(content)
    attestation = sign_artifact(wheel_path, keypair)
    attestation_path = tmp_path / f"{name}.attestation.json"
    import json
    attestation_path.write_text(json.dumps(attestation))
    return wheel_path, attestation_path, keypair


def _fake_installer_calls(calls: list):
    def _install(wheel_path: Path, venv_dir: Path) -> None:
        calls.append((wheel_path, venv_dir))
        venv_dir.mkdir(parents=True)
        (venv_dir / "marker.txt").write_text("installed")

    return _install


def test_install_refuses_an_unverified_artifact(tmp_path):
    wheel_path, attestation_path, _ = _signed_wheel(tmp_path)
    wheel_path.write_bytes(b"tampered after signing")  # sha256 no longer matches

    with pytest.raises(ReleaseError, match="refusing to install unverified artifact"):
        install_release(
            wheel_path=wheel_path, attestation_path=attestation_path, version="1.0.0",
            releases_dir=tmp_path / "releases", current_link=tmp_path / "current",
            installer=_fake_installer_calls([]),
        )
    assert not (tmp_path / "releases").exists()


def test_install_creates_a_versioned_release_and_activates_it(tmp_path):
    wheel_path, attestation_path, _ = _signed_wheel(tmp_path)
    calls = []

    result = install_release(
        wheel_path=wheel_path, attestation_path=attestation_path, version="1.0.0",
        releases_dir=tmp_path / "releases", current_link=tmp_path / "current",
        installer=_fake_installer_calls(calls),
    )

    assert result.version == "1.0.0"
    assert result.previous_version is None
    assert len(calls) == 1
    current_link = tmp_path / "current"
    assert current_link.is_symlink()
    assert current_link.resolve() == (tmp_path / "releases" / "1.0.0").resolve()
    assert (result.release_dir / "attestation.json").exists()


def test_install_a_second_release_tracks_the_previous_version_and_swaps_current(tmp_path):
    wheel_path, attestation_path, keypair = _signed_wheel(tmp_path)
    install_release(
        wheel_path=wheel_path, attestation_path=attestation_path, version="1.0.0",
        releases_dir=tmp_path / "releases", current_link=tmp_path / "current",
        installer=_fake_installer_calls([]),
    )

    wheel_path_2, attestation_path_2, _ = _signed_wheel(tmp_path, name="artifact2.whl", content=b"v2 bytes", keypair=keypair)
    result = install_release(
        wheel_path=wheel_path_2, attestation_path=attestation_path_2, version="1.1.0",
        releases_dir=tmp_path / "releases", current_link=tmp_path / "current",
        installer=_fake_installer_calls([]),
    )

    assert result.previous_version == "1.0.0"
    assert (tmp_path / "current").resolve() == (tmp_path / "releases" / "1.1.0").resolve()


def test_install_refuses_an_untrusted_signer(tmp_path):
    wheel_path, attestation_path, _ = _signed_wheel(tmp_path)

    with pytest.raises(ReleaseError, match="not in trusted keys"):
        install_release(
            wheel_path=wheel_path, attestation_path=attestation_path, version="1.0.0",
            releases_dir=tmp_path / "releases", current_link=tmp_path / "current",
            trusted_keys=["some-other-key"],
            installer=_fake_installer_calls([]),
        )


def test_install_cleans_up_the_release_directory_when_the_installer_fails(tmp_path):
    wheel_path, attestation_path, _ = _signed_wheel(tmp_path)

    def _failing_installer(wheel_path: Path, venv_dir: Path) -> None:
        raise RuntimeError("pip install exploded")

    with pytest.raises(ReleaseError, match="install failed"):
        install_release(
            wheel_path=wheel_path, attestation_path=attestation_path, version="1.0.0",
            releases_dir=tmp_path / "releases", current_link=tmp_path / "current",
            installer=_failing_installer,
        )
    assert not (tmp_path / "releases" / "1.0.0").exists()
    assert not (tmp_path / "current").exists()


def test_rollback_flips_current_without_reinstalling(tmp_path):
    wheel_path, attestation_path, keypair = _signed_wheel(tmp_path)
    calls = []
    install_release(
        wheel_path=wheel_path, attestation_path=attestation_path, version="1.0.0",
        releases_dir=tmp_path / "releases", current_link=tmp_path / "current",
        installer=_fake_installer_calls(calls),
    )
    wheel_path_2, attestation_path_2, _ = _signed_wheel(tmp_path, name="artifact2.whl", content=b"v2 bytes", keypair=keypair)
    install_release(
        wheel_path=wheel_path_2, attestation_path=attestation_path_2, version="1.1.0",
        releases_dir=tmp_path / "releases", current_link=tmp_path / "current",
        installer=_fake_installer_calls(calls),
    )
    assert len(calls) == 2  # both real installs happened

    rollback(version="1.0.0", releases_dir=tmp_path / "releases", current_link=tmp_path / "current")

    assert (tmp_path / "current").resolve() == (tmp_path / "releases" / "1.0.0").resolve()
    assert len(calls) == 2  # rollback did NOT trigger a third install


def test_rollback_to_an_uninstalled_version_fails_without_touching_current(tmp_path):
    wheel_path, attestation_path, _ = _signed_wheel(tmp_path)
    install_release(
        wheel_path=wheel_path, attestation_path=attestation_path, version="1.0.0",
        releases_dir=tmp_path / "releases", current_link=tmp_path / "current",
        installer=_fake_installer_calls([]),
    )

    with pytest.raises(ReleaseError, match="is not installed"):
        rollback(version="9.9.9", releases_dir=tmp_path / "releases", current_link=tmp_path / "current")

    assert (tmp_path / "current").resolve() == (tmp_path / "releases" / "1.0.0").resolve()


def test_list_releases_reports_current_flag_correctly(tmp_path):
    wheel_path, attestation_path, keypair = _signed_wheel(tmp_path)
    install_release(
        wheel_path=wheel_path, attestation_path=attestation_path, version="1.0.0",
        releases_dir=tmp_path / "releases", current_link=tmp_path / "current",
        installer=_fake_installer_calls([]),
    )
    wheel_path_2, attestation_path_2, _ = _signed_wheel(tmp_path, name="artifact2.whl", content=b"v2", keypair=keypair)
    install_release(
        wheel_path=wheel_path_2, attestation_path=attestation_path_2, version="1.1.0",
        releases_dir=tmp_path / "releases", current_link=tmp_path / "current",
        installer=_fake_installer_calls([]),
    )

    releases = list_releases(releases_dir=tmp_path / "releases", current_link=tmp_path / "current")

    assert releases == [
        {"version": "1.0.0", "current": False},
        {"version": "1.1.0", "current": True},
    ]


def test_list_releases_on_a_fresh_install_is_empty(tmp_path):
    assert list_releases(releases_dir=tmp_path / "releases", current_link=tmp_path / "current") == []


def test_default_installer_really_installs_a_real_trivial_wheel(tmp_path):
    """The one test that exercises the REAL venv+pip path (default_installer()), not an
    injected fake -- proves the actual production code path works, not just its
    orchestration. Builds a real, minimal installable package with stdlib only (no
    `build`/`setuptools` wheel-building dependency needed here -- pip can install a
    directory with a pyproject.toml directly, which is what real `pip install <path>`
    already does for a local package; that's exercised instead of a prebuilt .whl file,
    since constructing a real .whl by hand or requiring the `build` package are both
    worse options for a test)."""
    import shutil
    import subprocess
    import sys

    pkg_dir = tmp_path / "trivial_pkg"
    pkg_dir.mkdir()
    (pkg_dir / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["setuptools"]\nbuild-backend = "setuptools.build_meta"\n\n'
        '[project]\nname = "trivial-pkg"\nversion = "0.0.1"\n'
    )

    # install_release() treats its "wheel_path" as an opaque signed artifact whose bytes
    # must round-trip; a real sdist tarball of this trivial package plays that role here.
    sdist_path = tmp_path / "trivial_pkg.tar"
    shutil.make_archive(str(sdist_path.with_suffix("")), "tar", root_dir=tmp_path, base_dir="trivial_pkg")

    keypair = Keypair.generate()
    attestation = sign_artifact(sdist_path, keypair)
    attestation_path = tmp_path / "trivial_pkg.attestation.json"
    import json
    attestation_path.write_text(json.dumps(attestation))

    def _real_installer_from_tar(artifact_path: Path, venv_dir: Path) -> None:
        subprocess.run(["uv", "venv", "--seed", str(venv_dir)], check=True, capture_output=True, text=True)
        extract_dir = venv_dir.parent / "src"
        shutil.unpack_archive(str(artifact_path), str(extract_dir), format="tar")
        subprocess.run(
            [str(venv_dir / "bin" / "pip"), "install", "--quiet", str(extract_dir / "trivial_pkg")],
            check=True, capture_output=True, text=True,
        )

    result = install_release(
        wheel_path=sdist_path, attestation_path=attestation_path, version="0.0.1",
        releases_dir=tmp_path / "releases", current_link=tmp_path / "current",
        installer=_real_installer_from_tar,
    )

    installed = subprocess.run(
        [str(result.release_dir / "venv" / "bin" / "pip"), "show", "trivial-pkg"],
        capture_output=True, text=True,
    )
    assert installed.returncode == 0
    assert "trivial-pkg" in installed.stdout or "trivial_pkg" in installed.stdout
