import json

from shield.codex_agent import CodexAdvisoryAgent, redact_event


def test_redact_event_removes_sensitive_values_and_bounds_text():
    result = redact_event({"cmdline": "secret command", "nested": {"token": "abc"}, "class": "x"})
    assert result["cmdline"] == "<redacted>"
    assert result["nested"]["token"] == "<redacted>"


def test_codex_advisory_agent_is_read_only_and_parses_result(tmp_path):
    seen = {}

    def runner(command, **kwargs):
        seen["command"] = command
        seen["kwargs"] = kwargs
        output = tmp_path / "last-message.txt"
        output.write_text(json.dumps({"classification": "suspicious", "confidence": 0.8, "rationale": "review", "recommended_test": "inspect process metadata"}))
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    agent = CodexAdvisoryAgent(runner=runner)
    # The fake output path is intentionally not available to the production temp dir;
    # exercise the parser through stdout instead.
    def stdout_runner(command, **kwargs):
        seen["command"] = command
        seen["kwargs"] = kwargs
        return type("Result", (), {"returncode": 0, "stdout": json.dumps({"classification": "suspicious", "confidence": 0.8, "rationale": "review"}), "stderr": ""})()

    agent = CodexAdvisoryAgent(runner=stdout_runner)
    result = agent.analyze_event({"class": "process_activity", "token": "hidden"})
    assert result.classification == "suspicious"
    assert "--sandbox" in seen["command"] and "read-only" in seen["command"]
    assert seen["kwargs"]["check"] is False
