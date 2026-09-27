from shield.network_policy import NetworkActionRequest, NetworkGateConfig, NetworkIdentity, authorize_network_action


DEVICE = "sha256:" + "1" * 64
TARGET = "sha256:" + "2" * 64
IDEMPOTENCY = "sha256:" + "3" * 64


def identity(**overrides):
    values = {"device_ref": DEVICE, "source": "enrollment", "posture": "known", "confidence": 0.99, "freshness_seconds": 10}
    values.update(overrides)
    return NetworkIdentity(**values)


def request(**overrides):
    values = {"action": "block_flow", "target_ref": TARGET, "duration_seconds": 60, "idempotency_ref": IDEMPOTENCY}
    values.update(overrides)
    return NetworkActionRequest(**values)


def test_safe_request_is_preview_only_by_default():
    decision = authorize_network_action(identity(), request())
    assert decision.allowed is True
    assert decision.status == "preview"


def test_inferred_or_stale_identity_cannot_authorize():
    assert authorize_network_action(identity(source="inferred"), request()).reason_code == "IDENTITY_NOT_AUTHORITATIVE"
    assert authorize_network_action(identity(freshness_seconds=901), request()).reason_code == "IDENTITY_STALE"


def test_protected_path_and_blast_radius_are_denied():
    protected = NetworkGateConfig(protected_refs=frozenset({TARGET}))
    assert authorize_network_action(identity(), request(), protected).reason_code == "PROTECTED_PATH"
    assert authorize_network_action(identity(), request(affected_devices=2)).reason_code == "BLAST_RADIUS_DEVICES"


def test_wide_scope_requires_approval_and_expiry():
    assert authorize_network_action(identity(), request(scope="segment")).reason_code == "APPROVAL_REQUIRED_FOR_SCOPE"
    assert authorize_network_action(identity(), request(scope="segment", approval_ref="approval-1")).allowed is True
    assert authorize_network_action(identity(), request(duration_seconds=0)).reason_code == "EXPIRY_REQUIRED"


def test_live_action_requires_idempotency_and_can_be_explicitly_approved():
    assert authorize_network_action(identity(), request(dry_run=False, idempotency_ref="")).reason_code == "IDEMPOTENCY_REQUIRED"
    decision = authorize_network_action(identity(), request(dry_run=False))
    assert decision.status == "approved"
