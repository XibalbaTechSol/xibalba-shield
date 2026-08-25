from __future__ import annotations

import hashlib

import pytest

from shield.opa_local import PACKAGE_ROOT, PROFILES, selected_profile_metadata, supervised_opa, _query


@pytest.mark.parametrize("profile", sorted(PROFILES))
def test_selected_profile_metadata_is_bound_to_rego_bytes(profile):
    version, digest = selected_profile_metadata(profile)
    assert version == "1.0.0"
    assert digest == f"sha256:{hashlib.sha256(PROFILES[profile].read_bytes()).hexdigest()}"
    assert PROFILES[profile].is_relative_to(PACKAGE_ROOT)


def test_unknown_profile_fails_closed():
    with pytest.raises(ValueError, match="unsupported OPA profile"):
        selected_profile_metadata("all")


@pytest.mark.parametrize("profile", sorted(PROFILES))
def test_supervised_opa_real_profile_probe(profile):
    with supervised_opa(profile, timeout=5) as url:
        assert url.startswith("http://127.0.0.1:")
        result = _query(url, {
            "event": {"process": {"exe_path": "/tmp/ordinary"}},
            "ctx": {"registered_agent_ids": {}},
        })
        assert set(("allow", "action", "message", "rule_id", "name", "version")) <= set(result)


def test_supervised_opa_reports_missing_binary():
    with pytest.raises(FileNotFoundError):
        with supervised_opa("smb", opa_binary="/does/not/exist"):
            pass
