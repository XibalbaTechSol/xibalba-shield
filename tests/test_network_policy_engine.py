from shield.network_policy_engine import NetworkPolicyEngine


def test_network_engine_is_deterministic_and_hashes_policy():
    engine = NetworkPolicyEngine.from_dicts([
        {"rule_id": "block-candidate", "action": "deny", "reason_code": "ANOMALY", "match": {"flow.destination_class": "malicious_candidate"}},
        {"rule_id": "review-posture", "action": "isolate", "reason_code": "POSTURE_FAILURE", "match": {"device.posture": "noncompliant"}, "require_approval": True},
    ], version="network-1")
    observed = {"flow": {"destination_class": "malicious_candidate"}, "device": {"posture": "known"}}
    first = engine.evaluate(observed)
    second = engine.evaluate(observed)
    assert first == second
    assert first.action == "deny"
    assert first.policy_hash.startswith("sha256:")


def test_network_engine_first_match_and_safe_default():
    engine = NetworkPolicyEngine.from_dicts([
        {"rule_id": "new-destination", "action": "escalate", "match": {"flow.destination_class": ["new", "unknown"]}},
        {"rule_id": "allow-web", "action": "allow", "match": {"flow.service_class": "web"}},
    ])
    assert engine.evaluate({"flow": {"destination_class": "new", "service_class": "web"}}).rule_id == "new-destination"
    assert engine.evaluate({"flow": {"destination_class": "approved", "service_class": "web"}}).action == "allow"
    assert engine.evaluate({"flow": {"destination_class": "approved", "service_class": "ssh"}}).reason_code == "NO_MATCH"
