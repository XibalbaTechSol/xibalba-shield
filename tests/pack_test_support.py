"""Small pack-aware OPA seam for unit tests that do not need a live sidecar."""

from __future__ import annotations

from unittest.mock import Mock

from integrity_sdk.core.packs import LoadedPack

from shield.opa_local import load_signed_profile_pack
from shield.policy_engine import engine as policy_engine_module


def install_fake_opa(monkeypatch, *, profile: str = "smb", inject_pack: bool = True) -> Mock:
    """Patch PolicyEngine construction to use a verified pack and controllable OPA."""
    default_pack: LoadedPack = load_signed_profile_pack(profile)
    evaluator = Mock()
    evaluator.return_value = Mock(
        raw_result={
            "decision": "permit",
            "reason_code": "TEST_PERMIT",
            "action": "allow",
            "message": "test permit",
            "rule_id": "test-permit",
            "name": "Test permit",
            "version": "1.0.0",
        }
    )
    client = Mock()

    def query(_pack, _opa_input):
        if evaluator.side_effect is not None:
            effect = evaluator.side_effect
            if isinstance(effect, BaseException):
                raise effect
            return effect()
        result = evaluator.return_value
        return getattr(result, "raw_result", result)

    client.query.side_effect = query
    monkeypatch.setattr(policy_engine_module, "OpaClient", lambda _url: client)

    if inject_pack:
        original_init = policy_engine_module.PolicyEngine.__init__

        def init(self, opa_url="http://localhost:8181", *, pack=None):
            original_init(self, opa_url, pack=pack or default_pack)

        monkeypatch.setattr(policy_engine_module.PolicyEngine, "__init__", init)
    return evaluator
