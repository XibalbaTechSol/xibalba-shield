"""Coverage for shield/release/signing.py -- package-signing half of
docs/PRODUCTION_READINESS_PLAN.md §7 item 5."""

from __future__ import annotations

from integrity_sdk.did import Keypair

from shield.release import sha256_of, sign_artifact, verify_artifact


def _write_artifact(tmp_path, content: bytes = b"a fake wheel's real bytes"):
    path = tmp_path / "artifact.whl"
    path.write_bytes(content)
    return path


def test_sha256_of_matches_hashlib_directly(tmp_path):
    import hashlib

    path = _write_artifact(tmp_path, b"some real content")
    assert sha256_of(path) == hashlib.sha256(b"some real content").hexdigest()


def test_sign_then_verify_round_trip_with_no_trusted_keys_configured(tmp_path):
    path = _write_artifact(tmp_path)
    keypair = Keypair.generate()

    attestation = sign_artifact(path, keypair)
    result = verify_artifact(path, attestation)

    assert result.verified is True
    assert result.signer_public_key == attestation["signer_public_key"]


def test_verify_succeeds_when_signer_is_in_trusted_keys(tmp_path):
    path = _write_artifact(tmp_path)
    keypair = Keypair.generate()
    attestation = sign_artifact(path, keypair)

    result = verify_artifact(path, attestation, trusted_keys=[attestation["signer_public_key"]])
    assert result.verified is True


def test_verify_rejects_an_untrusted_signer(tmp_path):
    path = _write_artifact(tmp_path)
    attestation = sign_artifact(path, Keypair.generate())

    result = verify_artifact(path, attestation, trusted_keys=["some-other-base64-key"])
    assert result.verified is False
    assert "not in trusted keys" in result.reason


def test_verify_rejects_swapped_artifact_content(tmp_path):
    """The artifact on disk no longer matches what was signed (e.g. swapped after
    signing, or a version mismatch) -- must be rejected on the hash check, before
    signature verification even runs."""
    path = _write_artifact(tmp_path, b"original content")
    attestation = sign_artifact(path, Keypair.generate())

    path.write_bytes(b"swapped content -- not what was signed")
    result = verify_artifact(path, attestation)

    assert result.verified is False
    assert "sha256 mismatch" in result.reason


def test_verify_rejects_a_tampered_signature(tmp_path):
    path = _write_artifact(tmp_path)
    attestation = sign_artifact(path, Keypair.generate())
    # Flip the base64 signature's leading char to something else valid-base64 but wrong,
    # rather than reusing a signature computed over different signed fields entirely.
    original = attestation["signature"]
    attestation["signature"] = ("A" if original[0] != "A" else "B") + original[1:]

    result = verify_artifact(path, attestation)
    assert result.verified is False
    assert "does not verify" in result.reason


def test_verify_rejects_malformed_attestation_shape(tmp_path):
    path = _write_artifact(tmp_path)
    result = verify_artifact(path, {"sha256": sha256_of(path)})  # missing signature/signer_public_key
    assert result.verified is False
    assert "malformed attestation" in result.reason


def test_two_different_artifacts_produce_different_signed_hashes(tmp_path):
    keypair = Keypair.generate()
    path_a = tmp_path / "a.whl"
    path_a.write_bytes(b"content A")
    path_b = tmp_path / "b.whl"
    path_b.write_bytes(b"content B")

    a = sign_artifact(path_a, keypair)
    b = sign_artifact(path_b, keypair)
    assert a["sha256"] != b["sha256"]
