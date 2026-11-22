import json
import time
import pytest
from shield.advisories import build_remediation_plan, load_advisories, match_advisories

def test_advisory_source_loads_with_provenance(tmp_path):
    p = tmp_path / "db.json"
    p.write_text(json.dumps({"updated_at": time.time(), "advisories": [{"id":"CVE-1","package":"x","version":"1","severity":"high"}]}))
    source = load_advisories(p)
    result = match_advisories({"packages":[{"name":"x","version":"1"}]}, source)
    assert result["known_findings"][0]["id"] == "CVE-1"
    assert len(result["source_hash"]) == 64

def test_stale_source_is_rejected(tmp_path):
    p = tmp_path / "db.json"
    p.write_text(json.dumps({"updated_at": 1, "advisories": []}))
    with pytest.raises(ValueError, match="stale"):
        load_advisories(p)

def test_matching_is_bounded():
    source = {"source_hash":"h", "updated_at":1, "advisories":[{"id":str(i),"package":"x","version":"1"} for i in range(4)]}
    assert len(match_advisories({"packages":[{"name":"x","version":"1"}]}, source, max_findings=2)["known_findings"]) == 2


def test_findings_are_prioritized_and_preserve_fix_guidance():
    source = {"source_hash":"h", "updated_at":1, "advisories":[
        {"id":"low","package":"x","version":"1","severity":"low"},
        {"id":"critical","package":"x","version":"1","severity":"critical","fixed_version":"2"},
    ]}
    findings = match_advisories({"packages":[{"name":"x","version":"1"}]}, source)["known_findings"]
    assert findings[0]["id"] == "critical" and findings[0]["fixed_version"] == "2"


def test_remediation_plan_requires_approval_and_never_executes():
    plan = build_remediation_plan([{"id": "CVE-1", "package": "x", "version": "1", "fixed_version": "2", "priority": 4}], maintenance_window="sunday")
    assert plan["status"] == "approval_required"
    assert plan["actions"][0]["requires_approval"] is True
    assert plan["executed"] is False
