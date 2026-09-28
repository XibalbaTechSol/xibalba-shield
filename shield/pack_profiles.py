"""Which `policies/packs/<name>/` directory each built-in compliance profile resolves to.

Single source of truth for "profile name" -> pack directory -- before
docs/EXECUTION_PLAN.md A3's pack-signing migration this same three-name list existed
twice (`policy_engine.engine.EVENT_DEFAULTS_BY_PROFILE` and `opa_local.PROFILES`), and a
pack.yaml manifest is now the one place a profile's per-event-class no-match default is
declared -- `DeviceConfig.policy_profile` (config/loader.py) only needs to know which
directory to load and sign-verify, not a second copy of what's inside it.
"""

from __future__ import annotations

from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent

PACK_DIRS_BY_PROFILE: dict[str, Path] = {
    "smb": PACKAGE_ROOT / "policies/packs/smb",
    "professional-services": PACKAGE_ROOT / "policies/packs/professional-services",
    "regulated": PACKAGE_ROOT / "policies/packs/regulated",
}


def pack_dir_for_profile(profile: str) -> Path | None:
    """None for "" (not set) or an unrecognized profile -- callers decide what "no pack
    directory selected" means for them (e.g. cli.py falls back to --pack-dir)."""
    return PACK_DIRS_BY_PROFILE.get(profile)
