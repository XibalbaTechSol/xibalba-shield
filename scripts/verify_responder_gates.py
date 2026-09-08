#!/usr/bin/env python3
"""Exercise gated responders against disposable local targets and emit proof JSON.

Run as root on the deployment host. The script always removes its temporary
cgroup and nftables table. Base assurance proofs must be supplied explicitly;
runtime probes cannot manufacture identity, policy, audit, or approval evidence.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import grp
import os
from pathlib import Path
import signal
import socket
import subprocess
import time

from shield.agent_core.action_broker import ActionBroker
from shield.agent_core.network_blocker import NftFlowBlocker
from shield.agent_core.readiness import BASE_PROOFS, ProductionReadiness


def command(argv: list[str]) -> None:
    subprocess.run(argv, check=True, capture_output=True, text=True)


def prove_kill(details: dict[str, str]) -> None:
    child = subprocess.Popen(["/usr/bin/sleep", "60"])
    try:
        broker = ActionBroker(enable_destructive=True, readiness=ProductionReadiness.from_mapping(
            {**{key: True for key in BASE_PROOFS}, "kill_runtime_tested": True}
        ))
        broker.kill_process(child.pid)
        if child.wait(timeout=2) != -signal.SIGKILL:
            raise RuntimeError("disposable process did not exit from SIGKILL")
        details["kill_runtime_tested"] = f"disposable pid {child.pid} exited by SIGKILL"
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()


def prove_cgroup(details: dict[str, str]) -> None:
    root = Path("/sys/fs/cgroup")
    target = root / f"xibalba-shield-proof-{os.getpid()}"
    child = subprocess.Popen(["/usr/bin/sleep", "60"])
    try:
        target.mkdir()
        (target / "cgroup.procs").write_text(f"{child.pid}\n", encoding="ascii")
        broker = ActionBroker(enable_cgroup=True, readiness=ProductionReadiness.from_mapping(
            {**{key: True for key in BASE_PROOFS}, "cgroup_runtime_tested": True}
        ))
        broker.freeze_cgroup(target, pid=child.pid)
        if (target / "cgroup.freeze").read_text(encoding="ascii").strip() != "1":
            raise RuntimeError("cgroup did not enter frozen state")
        broker.resume(child.pid, cgroup_path=target)
        details["cgroup_runtime_tested"] = f"cgroup v2 freeze and resume passed for disposable pid {child.pid}"
    finally:
        child.terminate()
        child.wait(timeout=2)
        try:
            target.rmdir()
        except FileNotFoundError:
            pass


def prove_network(details: dict[str, str]) -> None:
    table = f"xibalba_proof_{os.getpid()}"
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        command(["nft", "add", "table", "inet", table])
        command(["nft", "add", "chain", "inet", table, "output", "{ type filter hook output priority -5; policy accept; }"])
        blocker = NftFlowBlocker(table=table)
        broker = ActionBroker(
            enable_network=True,
            block_network=blocker,
            readiness=ProductionReadiness.from_mapping(
                {**{key: True for key in BASE_PROOFS}, "network_runtime_tested": True}
            ),
        )
        broker.block_flow({"protocol": "tcp", "dst_ip": "127.0.0.1", "dst_port": port})
        probe = socket.socket()
        probe.settimeout(0.4)
        try:
            probe.connect(("127.0.0.1", port))
        except (TimeoutError, OSError):
            pass
        else:
            raise RuntimeError("scoped nftables rule did not block the disposable endpoint")
        finally:
            probe.close()
        details["network_runtime_tested"] = f"nftables blocked disposable 127.0.0.1:{port}/tcp endpoint"
    finally:
        listener.close()
        subprocess.run(["nft", "delete", "table", "inet", table], capture_output=True, text=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--group", default="xibalba-shield", help="agent service group allowed to read the proof")
    parser.add_argument(
        "--base-proof", action="append", default=[], metavar="NAME=DETAIL",
        help="repeat for every non-runtime proof: " + ", ".join(BASE_PROOFS),
    )
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("root is required for cgroup and nftables runtime proof")
    evidence = dict(item.split("=", 1) for item in args.base_proof if "=" in item)
    missing = [key for key in BASE_PROOFS if not evidence.get(key)]
    if missing:
        parser.error("missing base proof evidence: " + ", ".join(missing))

    details = dict(evidence)
    prove_kill(details)
    prove_cgroup(details)
    prove_network(details)
    proofs = {key: True for key in BASE_PROOFS}
    proofs.update(kill_runtime_tested=True, cgroup_runtime_tested=True, network_runtime_tested=True)
    payload = {
        "schema": "xibalba.responder-readiness.v1",
        "device_id": args.device_id,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "proofs": proofs,
        "details": details,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chown(args.output, 0, grp.getgrnam(args.group).gr_gid)
    os.chmod(args.output, 0o640)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
