"""Pytest configuration and platform compatibility shims for Shield tests."""

from __future__ import annotations

import os
import sys
import types

if sys.platform == "win32":
    # 1. Provide an in-memory fcntl shim for Windows so integrity_sdk.bcc imports cleanly
    if "fcntl" not in sys.modules:
        fcntl_mock = types.ModuleType("fcntl")
        fcntl_mock.LOCK_SH = 1
        fcntl_mock.LOCK_EX = 2
        fcntl_mock.LOCK_NB = 4
        fcntl_mock.LOCK_UN = 8
        fcntl_mock.flock = lambda fd, op: None
        sys.modules["fcntl"] = fcntl_mock

    # 2. Provide ThreadingUnixStreamServer shim for socketserver on Windows
    import socketserver

    if not hasattr(socketserver, "ThreadingUnixStreamServer"):
        class _DummyThreadingUnixStreamServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
            pass

        socketserver.ThreadingUnixStreamServer = _DummyThreadingUnixStreamServer  # type: ignore[attr-defined]

    # 3. Provide os.geteuid fallback for Windows
    if not hasattr(os, "geteuid"):
        os.geteuid = lambda: 1000  # type: ignore[attr-defined]

    # 4. Ignore Unix-socket-daemon specific test suites on Windows
    collect_ignore = [
        "test_gate_daemon.py",
        "test_gate_receipts.py",
        "test_privileged_socket_sensor.py",
    ]
