# Regression guard (2026-09-27): an unwritable Cortex outbox must surface as an exception
# from the provider, which `shield run` catches so enforcement keeps running.
import os, pytest
from shield.agent_core.cortex_memory import CortexMemoryProvider

def test_from_environment_raises_on_unwritable_outbox(tmp_path, monkeypatch):
    # Reproduce the failure the CLI now guards: an outbox the process cannot create. A regular file where the outbox's
    # directory must be fails for every user, root included (a chmod-based read-only directory only fails for non-root).
    locked = tmp_path / "cortex"; locked.write_text("a file, not a directory")
    monkeypatch.setenv("XIBALBA_CORTEX_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("XIBALBA_CORTEX_TOKEN", "t")
    monkeypatch.setenv("XIBALBA_AGENT_ID", "did:integrity:test")
    monkeypatch.setenv("XIBALBA_CORTEX_OUTBOX", str(locked / "outbox.sqlite3"))
    with pytest.raises(Exception):
        CortexMemoryProvider.from_environment(device_id="dev")
