"""A valid session must stay valid under concurrent requests.

Why this suite exists: on 2026-11-15 the Render console's polling (billing + usage every 5 s,
two requests at once) made a valid session flip 200 -> 401 -> 200, and the backend logged
`IndexError: tuple index out of range` inside `session_for_token`. The backend serves requests
on a thread pool over ONE shared sqlite3 connection. `_ThreadSafeConnection.execute` held the
lock only while the statement started and returned a live cursor, so `.fetchone()` stepped that
cursor outside the lock while other threads ran statements on the same connection.
"""

from __future__ import annotations

import threading
from pathlib import Path

from shield.backend.store import ShieldStore

THREADS = 16
ROUNDS = 150


def _make_sessions(store: ShieldStore, n: int) -> list[tuple[str, str]]:
    sessions = []
    for i in range(n):
        tenant = f"race-tenant-{i}"
        account = store.create_account(tenant_id=tenant, email=f"race{i}@example.com", password="pw-" + "x" * 16, display_name=f"Race {i}")
        token = store.issue_account_session(account_id=account["id"], tenant_id=tenant)
        sessions.append((token, tenant))
    return sessions


def test_session_lookup_is_stable_under_concurrent_requests(tmp_path: Path) -> None:
    store = ShieldStore(tmp_path / "shield.db")
    sessions = _make_sessions(store, THREADS)
    failures: list[str] = []
    start = threading.Barrier(THREADS)

    def worker(token: str, tenant: str) -> None:
        start.wait()
        for _ in range(ROUNDS):
            try:
                session = store.session_for_token(token)
            except Exception as exc:  # the production failure was an IndexError here
                failures.append(f"{type(exc).__name__}: {exc}")
                continue
            if session is None or session["tenant_id"] != tenant:
                failures.append(f"lost session for {tenant}: {session!r}")

    threads = [threading.Thread(target=worker, args=s) for s in sessions]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not failures, f"{len(failures)} bad lookups out of {THREADS * ROUNDS}; first: {failures[:3]}"
