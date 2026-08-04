#!/usr/bin/env python3
"""
Measures the real RAM/CPU footprint of the Shield agent-core pipeline against spec §3's
binding resource budget: RAM ceiling <=90MB, CPU ceiling <=3-5% sustained.

SCOPE, stated plainly: this measures the Python agent-core process (Agent Core + Policy
Engine + Guardrail Hooks + Integrity Exporter), driven by DevModeSensor at a configurable
rate. It does NOT include the real Linux eBPF kernel-sensor overhead -- process_exec and
file_write are separately verified (see shield/sensors/ebpf/README.md) but LOADING an eBPF
program needs root, which this script does not require or request. eBPF programs also do
their filtering/capture work in KERNEL space with a cheap perf-buffer handoff to userspace,
which is a fundamentally different (and, by design, much smaller) cost than what this script
measures. Someone who wants the full picture including kernel-sensor overhead needs a
separate root-run measurement; this script establishes the userspace baseline honestly, not
the whole system.

Uses `resource.getrusage` (POSIX stdlib, always available on Linux -- no new dependency):
`ru_maxrss` for peak RSS, and CPU time delta (`ru_utime + ru_stime`) divided by wall-clock
elapsed for a real CPU-percent figure, the same definition spec §3's "3-5% sustained" implies
(fraction of one core consumed per wall-clock second, averaged over the run).

Runs two scenarios:
  1. STRESS: DevModeSensor at its fastest rate (interval_sec=0) for `--stress-seconds` --
     reveals real per-event processing cost, not just idle overhead.
  2. IDLE: DevModeSensor at its default background rate (1 event/sec) for `--idle-seconds`
     -- closer to what spec §3 actually means by "sustained."

Each scenario runs both WITH a real IntegrityExporter (against `--bcc-middleware-url`, real
BCC signing + a real HTTP POST per event -- self-skips to a no-op exporter if unreachable,
logged, never silently substituted) and WITHOUT one (`--no-exporter`), so network/signing
overhead is visible as its own line rather than folded invisibly into one number.
"""

from __future__ import annotations

import argparse
import resource
import time

from shield.agent_core import AgentRegistry, DeviceContext, EventRouter
from shield.policy_engine import PolicyEngine
from shield.schemas.policy_rule import Condition, PolicyRule, RuleAction, RuleScope
from shield.sensors import DevModeSensor


class _NullExporter:
    """Explicitly not a mock of a real exporter -- a deliberate, labeled no-op used only to
    isolate agent-core/policy-engine overhead from exporter network/signing cost in the
    IDLE/STRESS-without-exporter scenarios below."""

    def export_event(self, event) -> None:
        pass

    def export_decision(self, decision) -> dict:
        return {"authorized": True}


def _real_exporter(bcc_middleware_url: str):
    """Returns a real IntegrityExporter if bcc_middleware is reachable, or None (logged) if
    not -- never a silent substitution."""
    import socket
    from urllib.parse import urlparse

    parsed = urlparse(bcc_middleware_url)
    host, port = parsed.hostname or "localhost", parsed.port or 80
    try:
        with socket.create_connection((host, port), timeout=1.0):
            pass
    except OSError:
        print(f"  (bcc_middleware not reachable at {bcc_middleware_url} -- skipping WITH-exporter scenario)")
        return None

    from shield.integrity_exporter import IntegrityExporter

    return IntegrityExporter(bcc_middleware_url=bcc_middleware_url, agent_label="xibalba-shield-resource-bench")


def _sample_rules() -> list[PolicyRule]:
    """A realistic, non-trivial rule set -- an empty rule list would understate real
    per-event evaluation cost, since every event would hit the cheap `_no_match` path."""
    return [
        PolicyRule(
            rule_id="deny-shadow-ai", name="Deny unregistered shadow AI", version="1.0.0",
            scope=RuleScope(),
            conditions=[Condition(type="agent", match={"registered": [False]})],
            actions=[RuleAction(type="deny", message="unregistered agent")],
        ),
        PolicyRule(
            rule_id="flag-high-risk-inference", name="Flag high-risk inference", version="1.0.0",
            scope=RuleScope(),
            conditions=[Condition(type="activity", match={"risk_level": ["high"]})],
            actions=[RuleAction(type="escalate", message="high risk inference")],
        ),
        PolicyRule(
            rule_id="log-network", name="Log all network flows", version="1.0.0",
            scope=RuleScope(),
            conditions=[Condition(type="process", match={"name": ["python.exe"]})],
            actions=[RuleAction(type="log_only")],
        ),
    ]


class ScenarioResult:
    def __init__(self, count: int, wall_delta: float, cpu_delta: float, peak_rss_mb: float):
        self.count = count
        self.wall_delta = wall_delta
        self.cpu_delta = cpu_delta  # CPU-seconds actually consumed
        self.peak_rss_mb = peak_rss_mb

    @property
    def cpu_percent(self) -> float:
        """CPU consumed as a percentage of one core, averaged over wall-clock time --
        meaningful ONLY at the event rate this scenario actually ran at. See
        per_event_us for the rate-independent figure."""
        return 100.0 * self.cpu_delta / self.wall_delta if self.wall_delta > 0 else 0.0

    @property
    def per_event_us(self) -> float:
        """CPU microseconds consumed per event -- rate-independent, so THIS is what
        should be projected to any assumed real-world event rate, not cpu_percent from
        a synthetic max-throughput run compared directly against a budget meant for
        realistic sustained load."""
        return 1_000_000.0 * self.cpu_delta / self.count if self.count > 0 else 0.0


def _run_scenario(name: str, seconds: float, interval_sec: float, exporter) -> ScenarioResult:
    device = DeviceContext(device_id="bench-device", tenant_id="bench", device_role="workstation")
    registry = AgentRegistry()
    registry.register("copilot-agent", "Copilot")  # one of DevModeSensor's sample agent_ids, so
    # the "registered" condition actually exercises both branches, not just the unregistered one
    router = EventRouter(
        device=device, registry=registry, policy_engine=PolicyEngine(rules=_sample_rules()),
        exporter=exporter, guardrail_hooks=[],
    )
    sensor = DevModeSensor(device_id="bench-device", interval_sec=interval_sec, seed=42)

    start_rusage = resource.getrusage(resource.RUSAGE_SELF)
    start_wall = time.monotonic()
    deadline = start_wall + seconds

    count = 0
    for event in sensor.events():
        router.handle(event)
        count += 1
        if time.monotonic() >= deadline:
            break

    end_rusage = resource.getrusage(resource.RUSAGE_SELF)
    end_wall = time.monotonic()

    cpu_delta = (end_rusage.ru_utime + end_rusage.ru_stime) - (start_rusage.ru_utime + start_rusage.ru_stime)
    wall_delta = end_wall - start_wall
    peak_rss_mb = end_rusage.ru_maxrss / 1024  # ru_maxrss is KB on Linux

    result = ScenarioResult(count, wall_delta, cpu_delta, peak_rss_mb)
    print(f"  {name}: {count} events in {wall_delta:.1f}s -- "
          f"{result.cpu_percent:.2f}% CPU at this rate ({result.per_event_us:.1f} µs/event), "
          f"peak RSS {peak_rss_mb:.1f} MB")
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stress-seconds", type=float, default=15.0)
    ap.add_argument("--idle-seconds", type=float, default=15.0)
    ap.add_argument("--bcc-middleware-url", default="http://localhost:8000")
    ap.add_argument("--no-exporter", action="store_true", help="skip the WITH-exporter scenarios entirely")
    args = ap.parse_args()

    budget_ram_mb = 90.0
    budget_cpu_pct = 5.0  # spec §3's upper bound; 3% is the lower bound of the stated range

    print(f"Resource budget (spec §3): RAM <= {budget_ram_mb} MB, CPU <= {budget_cpu_pct}% sustained\n")

    results: dict[str, "ScenarioResult"] = {}

    print("Without exporter (agent core + policy engine only):")
    results["stress_no_exporter"] = _run_scenario(
        "STRESS", args.stress_seconds, interval_sec=0, exporter=_NullExporter())
    results["idle_no_exporter"] = _run_scenario(
        "IDLE", args.idle_seconds, interval_sec=1.0, exporter=_NullExporter())

    if not args.no_exporter:
        exporter = _real_exporter(args.bcc_middleware_url)
        if exporter is not None:
            print("\nWith real IntegrityExporter (real BCC signing + real HTTP POST per event):")
            results["stress_with_exporter"] = _run_scenario(
                "STRESS", args.stress_seconds, interval_sec=0, exporter=exporter)
            results["idle_with_exporter"] = _run_scenario(
                "IDLE", args.idle_seconds, interval_sec=1.0, exporter=exporter)
            exporter.flush()

    # STRESS scenarios run at ~tens of thousands of events/sec -- far beyond any
    # plausible real device's security-event rate, so their raw cpu_percent (which
    # saturates a core by design, since the loop never sleeps) is NOT a meaningful
    # comparison against a budget meant for realistic sustained load. per_event_us IS
    # rate-independent, so project it to a genuinely busy device (10 events/sec,
    # already a lot of process/file/network activity to police) instead.
    stress_results = {k: v for k, v in results.items() if k.startswith("stress_")}
    idle_results = {k: v for k, v in results.items() if k.startswith("idle_")}

    assumed_busy_rate = 10  # events/sec
    worst_per_event_us = max(r.per_event_us for r in stress_results.values())
    projected_cpu_at_busy_rate = worst_per_event_us * assumed_busy_rate / 1_000_000.0 * 100.0

    worst_idle_cpu = max(r.cpu_percent for r in idle_results.values())
    worst_ram = max(r.peak_rss_mb for r in results.values())

    print(f"\nAgainst budget (RAM <= {budget_ram_mb} MB, CPU <= {budget_cpu_pct}% sustained):")
    print(f"  IDLE-rate CPU (1 event/sec, realistic background): {worst_idle_cpu:.3f}% "
          f"({'within' if worst_idle_cpu <= budget_cpu_pct else 'EXCEEDS'} budget)")
    print(f"  Projected CPU at {assumed_busy_rate} events/sec (a genuinely busy device), "
          f"from measured per-event cost: {projected_cpu_at_busy_rate:.3f}% "
          f"({'within' if projected_cpu_at_busy_rate <= budget_cpu_pct else 'EXCEEDS'} budget)")
    print(f"  Peak RSS across all scenarios: {worst_ram:.1f} MB "
          f"({'within' if worst_ram <= budget_ram_mb else 'EXCEEDS'} budget)")
    print(f"  (STRESS scenarios' raw ~{max(r.cpu_percent for r in stress_results.values()):.0f}% CPU "
          f"figures are NOT compared against the budget -- that's a synthetic max-throughput "
          f"saturation number, not a realistic sustained rate; see per-event µs above instead)")

    within_budget = (
        worst_idle_cpu <= budget_cpu_pct
        and projected_cpu_at_busy_rate <= budget_cpu_pct
        and worst_ram <= budget_ram_mb
    )
    return 0 if within_budget else 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
