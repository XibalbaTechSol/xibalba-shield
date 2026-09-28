"""Resolve which Integrity pack a `shield run` invocation enforces (docs/EXECUTION_PLAN.md A3).

Precedence: `--pack-dir` (explicit operator override) > `device_config.policy_profile` (one
of the three built-in verticals, operator-signed) > the built-in `smb` pack, self-signed
with a fresh ephemeral key every run.

The ephemeral-signed fallback exists so `shield run`'s zero-config default keeps enforcing
today's permissive log_only-everywhere behavior (this is the posture this machine's own
live `xibalba-shield` deployment already runs under) instead of denying every event the
moment nothing is explicitly configured. A verified-but-throwaway-signed pack is still real
"what's enforced is what's signed" enforcement -- decision/reason_code/pack_hash all still
come from an actually-verified `LoadedPack` -- it just carries no stable, auditable signer
identity across restarts. An operator who wants that signs the profile themselves once
(`shield sign-pack`) and sets `policy_profile` + `trusted_pack_signers`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from integrity_sdk.core.packs import LoadedPack, PackError, load_pack

from .config.loader import DeviceConfig
from .opa_local import load_signed_profile_pack
from .pack_profiles import PACK_DIRS_BY_PROFILE

FALLBACK_PROFILE = "smb"


class PackLoadError(Exception):
    """A pack could not be resolved/verified; `cli.py` reports this and exits 1."""


def resolve_pack(
    device_config: DeviceConfig, *, pack_dir: Optional[Path] = None, trusted_pack_signers: Optional[list[str]] = None,
) -> LoadedPack:
    if pack_dir is not None:
        signers = trusted_pack_signers or device_config.trusted_pack_signers
        if not signers:
            raise PackLoadError(f"--pack-dir {pack_dir} given with no trusted pack signers configured")
        try:
            return load_pack(pack_dir, trusted_signers=signers)
        except PackError as exc:
            raise PackLoadError(f"unable to load pack at {pack_dir}: {exc}") from exc

    if device_config.policy_profile:
        built_in_dir = PACK_DIRS_BY_PROFILE[device_config.policy_profile]  # validated at config-load time
        if not device_config.trusted_pack_signers:
            raise PackLoadError(
                f"policy_profile {device_config.policy_profile!r} is set but trusted_pack_signers is "
                f"empty -- sign {built_in_dir} with `shield sign-pack` and trust that key first"
            )
        try:
            return load_pack(built_in_dir, trusted_signers=device_config.trusted_pack_signers)
        except PackError as exc:
            raise PackLoadError(
                f"unable to load pack for profile {device_config.policy_profile!r}: {exc}"
            ) from exc

    try:
        return load_signed_profile_pack(FALLBACK_PROFILE)
    except (PackError, ValueError, OSError) as exc:
        raise PackLoadError(f"unable to load the default {FALLBACK_PROFILE!r} pack: {exc}") from exc
