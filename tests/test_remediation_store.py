import pytest
from shield.remediation_store import RemediationPlanStore

def test_plan_lifecycle_is_durable_and_non_executing(tmp_path):
    p = {"actions": [{"package": "x", "to_version": "2"}], "executed": False}
    store = RemediationPlanStore(tmp_path / "plans.db")
    plan_id = store.create(p)
    assert store.get(plan_id)["status"] == "pending"
    store.transition(plan_id, "approved")
    reopened = RemediationPlanStore(tmp_path / "plans.db")
    result = reopened.get(plan_id)
    assert result["status"] == "approved" and result["executed"] is False

def test_unknown_plan_and_invalid_transition_fail(tmp_path):
    store = RemediationPlanStore(tmp_path / "plans.db")
    with pytest.raises(KeyError): store.transition("missing", "approved")
    with pytest.raises(ValueError): store.transition("missing", "executed")
