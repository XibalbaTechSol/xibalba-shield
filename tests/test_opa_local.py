from __future__ import annotations

import pytest

from integrity_sdk.core.opa import OpaClient

from shield.opa_local import load_signed_profile_pack, supervised_opa
from shield.pack_profiles import PACKAGE_ROOT, PACK_DIRS_BY_PROFILE


@pytest.mark.parametrize("profile", sorted(PACK_DIRS_BY_PROFILE))
def test_selected_profile_pack_is_verified_and_bound_to_package(profile):
    pack = load_signed_profile_pack(profile)
    assert pack.manifest["version"] == "1.0.0"
    assert pack.pack_hash.startswith("sha256:")
    assert PACK_DIRS_BY_PROFILE[profile].is_relative_to(PACKAGE_ROOT)
    assert pack.policy_modules()


def test_unknown_profile_fails_closed():
    with pytest.raises(ValueError, match="unsupported policy profile"):
        load_signed_profile_pack("all")


@pytest.mark.parametrize("profile", sorted(PACK_DIRS_BY_PROFILE))
def test_supervised_opa_real_profile_probe(profile):
    with supervised_opa(profile, timeout=5) as (url, pack):
        assert url.startswith("http://127.0.0.1:")
        client = OpaClient(url)
        client.install(pack)
        result = client.query(pack, {
            "event": {"process": {"exe_path": "/tmp/ordinary"}},
            "ctx": {"registered_agent_ids": {}},
        })
        assert set(("allow", "action", "message", "rule_id", "name", "version")) <= set(result)


def test_supervised_opa_reports_missing_binary():
    with pytest.raises(FileNotFoundError):
        with supervised_opa("smb", opa_binary="/does/not/exist"):
            pass
