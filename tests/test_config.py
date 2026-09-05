"""
Tests for the local-file half of the config/update module (shield/config/, spec §4.6).

Every test writes a real JSON file to a real temp directory (pytest's `tmp_path`) and reads
it back through the real loader -- no mocked filesystem, no fixture-shaped-like-JSON strings
standing in for a file that was never actually written.
"""

from __future__ import annotations

import json

import pytest

from shield.config import ConfigError, DeviceConfig, load_device_config, load_policy_bundle, load_policy_rules, sign_policy_bundle


# ---- load_policy_rules ----

def test_loads_real_rules_in_file_order(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({
        "rules": [
            {"rule_id": "a", "name": "A", "version": "1.0.0",
             "conditions": [{"type": "process", "match": {"name": ["python"]}}],
             "actions": [{"type": "allow"}]},
            {"rule_id": "b", "name": "B", "version": "1.0.0",
             "conditions": [{"type": "process", "match": {"name": ["python"]}}],
             "actions": [{"type": "deny"}]},
        ]
    }))

    rules = load_policy_rules(path)

    assert [r.rule_id for r in rules] == ["a", "b"]  # order preserved -- first-match-wins depends on it
    assert rules[0].actions[0].type == "allow"
    assert rules[1].actions[0].type == "deny"


def test_loads_policy_bundle_metadata_and_hash(tmp_path):
    path = tmp_path / "rules.json"
    raw = {
        "policy_version": "pilot-2026.08",
        "rules": [
            {"rule_id": "a", "name": "A", "version": "1.0.0",
             "conditions": [{"type": "process", "match": {"name": ["python"]}}],
             "actions": [{"type": "allow"}]},
        ],
    }
    path.write_text(json.dumps(raw))

    bundle = load_policy_bundle(path)

    assert bundle.version == "pilot-2026.08"
    assert bundle.hash.startswith("sha256:")
    assert len(bundle.hash) == len("sha256:") + 64
    assert [r.rule_id for r in bundle.rules] == ["a"]


def test_missing_file_raises_config_error(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_policy_rules(tmp_path / "does-not-exist.json")


def test_invalid_json_raises_config_error(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text("{not valid json")

    with pytest.raises(ConfigError, match="not valid JSON"):
        load_policy_rules(path)


def test_missing_rules_key_raises_config_error(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({"not_rules": []}))

    with pytest.raises(ConfigError, match='"rules"'):
        load_policy_rules(path)


def test_rules_not_a_list_raises_config_error(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({"rules": "not-a-list"}))

    with pytest.raises(ConfigError, match="must be an array"):
        load_policy_rules(path)


def test_one_bad_rule_fails_the_whole_bundle_not_silently_dropped(tmp_path):
    """A policy engine that silently loaded fewer rules than the operator intended would
    fail-open in the worst possible way without saying so."""
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({
        "rules": [
            {"rule_id": "a", "name": "A", "version": "1.0.0", "conditions": [], "actions": []},
            {"name": "missing rule_id"},  # invalid: rule_id is required
        ]
    }))

    with pytest.raises(ConfigError, match="rules\\[1\\]"):
        load_policy_rules(path)


def test_empty_rules_list_is_valid_not_an_error(tmp_path):
    """An explicit empty rule set is a legitimate config (deny-nothing default-allow
    posture) -- distinct from a missing/malformed file, which IS an error."""
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({"rules": []}))

    assert load_policy_rules(path) == []


# ---- load_device_config ----

def test_loads_minimal_device_config(tmp_path):
    path = tmp_path / "device.json"
    path.write_text(json.dumps({"device_id": "dev-1"}))

    config = load_device_config(path)

    assert config.device_id == "dev-1"
    assert config.tenant_id == ""  # default, matching DeviceConfig's own default
    assert config.bcc_middleware_url == "http://localhost:8000"


def test_loads_full_device_config_with_feature_flags(tmp_path):
    path = tmp_path / "device.json"
    path.write_text(json.dumps({
        "device_id": "dev-1",
        "tenant_id": "tenant-xyz",
        "device_role": "clinical_desktop",
        "bcc_middleware_url": "https://bcc.example.com",
        "oracle_url": "https://oracle.example.com",
        "feature_flags": {"strict_mode": True},
        "sensitive_paths": ["/home/*/.ssh/*", "/var/secrets/*"],
        "trusted_policy_hashes": ["sha256:abc"],
        "reject_policy_downgrades": True,
    }))

    config = load_device_config(path)

    assert config.tenant_id == "tenant-xyz"
    assert config.flag("strict_mode") is True
    assert config.flag("unknown_flag") is False  # unknown flags default safely, don't raise
    assert config.sensitive_paths == ["/home/*/.ssh/*", "/var/secrets/*"]
    assert config.trusted_policy_hashes == ["sha256:abc"]
    assert config.reject_policy_downgrades is True


def test_device_config_sensitive_paths_must_be_a_list(tmp_path):
    path = tmp_path / "device.json"
    path.write_text(json.dumps({"device_id": "dev-1", "sensitive_paths": "/tmp/*"}))

    with pytest.raises(ConfigError, match="sensitive_paths"):
        load_device_config(path)


def test_device_config_trusted_policy_hashes_must_be_a_list(tmp_path):
    path = tmp_path / "device.json"
    path.write_text(json.dumps({"device_id": "dev-1", "trusted_policy_hashes": "sha256:abc"}))

    with pytest.raises(ConfigError, match="trusted_policy_hashes"):
        load_device_config(path)


def test_device_config_reject_policy_downgrades_must_be_boolean(tmp_path):
    path = tmp_path / "device.json"
    path.write_text(json.dumps({"device_id": "dev-1", "reject_policy_downgrades": "yes"}))

    with pytest.raises(ConfigError, match="reject_policy_downgrades"):
        load_device_config(path)


def test_device_config_missing_device_id_raises_config_error(tmp_path):
    path = tmp_path / "device.json"
    path.write_text(json.dumps({"tenant_id": "tenant-xyz"}))

    with pytest.raises(ConfigError, match="device_id"):
        load_device_config(path)


def test_device_config_unknown_field_raises_config_error(tmp_path):
    """A typo'd field name (e.g. "tennant_id") silently doing nothing is exactly the
    fail-open-by-accident this loader refuses to allow."""
    path = tmp_path / "device.json"
    path.write_text(json.dumps({"device_id": "dev-1", "tennant_id": "typo"}))

    with pytest.raises(ConfigError, match="unknown field"):
        load_device_config(path)


def test_device_config_loads_signing_fields(tmp_path):
    path = tmp_path / "device.json"
    path.write_text(json.dumps({
        "device_id": "dev-1",
        "trusted_signing_keys": ["a-base64-key=="],
        "require_signed_policy": True,
    }))

    config = load_device_config(path)

    assert config.trusted_signing_keys == ["a-base64-key=="]
    assert config.require_signed_policy is True


def test_device_config_trusted_signing_keys_must_be_a_list(tmp_path):
    path = tmp_path / "device.json"
    path.write_text(json.dumps({"device_id": "dev-1", "trusted_signing_keys": "not-a-list"}))

    with pytest.raises(ConfigError, match="trusted_signing_keys"):
        load_device_config(path)


def test_device_config_require_signed_policy_must_be_boolean(tmp_path):
    path = tmp_path / "device.json"
    path.write_text(json.dumps({"device_id": "dev-1", "require_signed_policy": "yes"}))

    with pytest.raises(ConfigError, match="require_signed_policy"):
        load_device_config(path)


# ---- signed policy bundles ----

def _real_policy(**extra) -> dict:
    return {
        "policy_version": "v-1",
        "rules": [{"rule_id": "a", "name": "a", "version": "1.0.0", "conditions": [], "actions": [{"type": "allow"}]}],
        **extra,
    }


def test_loads_a_validly_signed_bundle(tmp_path):
    from integrity_sdk.did import Keypair

    keypair = Keypair.generate()
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(sign_policy_bundle(_real_policy(), keypair)))

    bundle = load_policy_bundle(path)

    assert bundle.signed is True
    assert len(bundle.rules) == 1
    assert bundle.signer_public_key is not None


def test_unsigned_bundle_still_loads_when_signing_not_required(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(_real_policy()))

    bundle = load_policy_bundle(path)

    assert bundle.signed is False
    assert len(bundle.rules) == 1


def test_require_signed_policy_rejects_an_unsigned_bundle(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(_real_policy()))

    with pytest.raises(ConfigError, match="unsigned bundle rejected"):
        load_policy_bundle(path, require_signed_policy=True)


def test_require_signed_policy_rejects_an_invalidly_signed_bundle(tmp_path):
    from integrity_sdk.did import Keypair

    keypair = Keypair.generate()
    other = Keypair.generate()
    doc = sign_policy_bundle(_real_policy(), keypair)
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(doc))

    with pytest.raises(ConfigError, match="signature verification failed"):
        load_policy_bundle(
            path,
            require_signed_policy=True,
            trusted_signing_keys=["not-the-real-key"],
        )


def test_require_signed_policy_accepts_a_trusted_signed_bundle(tmp_path):
    import base64

    from integrity_sdk.did import Keypair

    keypair = Keypair.generate()
    trusted = base64.b64encode(keypair.public_bytes()).decode("ascii")
    doc = sign_policy_bundle(_real_policy(), keypair)
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(doc))

    bundle = load_policy_bundle(path, require_signed_policy=True, trusted_signing_keys=[trusted])

    assert bundle.signed is True
    assert bundle.signer_public_key == trusted


def test_expired_bundle_loads_but_is_reported_expired(tmp_path):
    from datetime import datetime, timedelta, timezone

    from integrity_sdk.did import Keypair

    keypair = Keypair.generate()
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    doc = sign_policy_bundle(_real_policy(expires_at=past), keypair)
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(doc))

    # Not required-signed, so the bundle still loads (expiry is enforced by the hot
    # reloader re-checking it continuously, see test_hot_reload.py) -- but it's
    # correctly reported as NOT verified/signed, since signature verification itself
    # includes the expiry check.
    bundle = load_policy_bundle(path)

    assert bundle.signed is False
    assert bundle.expires_at == past
