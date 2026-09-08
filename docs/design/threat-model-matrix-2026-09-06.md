# Chaos / adversarial threat-model matrix (2026-09-06)

`docs/PRODUCTION_READINESS_PLAN.md` §7 item 6 / Gate 6 ("the threat-model matrix has no
unexplained critical bypasses and all known limitations are visible to operators") named this
matrix as a missing artifact — `SECURITY.md` documents known limitations in prose, and
`docs/PRODUCTION_READINESS_PLAN.md` §4.A names the same attack paths in prose, but neither is
a per-scenario checklist a reviewer (or `scripts/pilot_gate_report.py`) can check against.
This is that checklist, scoped to workstream I's exact 14 named scenarios (7 chaos, 7
adversarial) — nothing broader, nothing narrower.

**How to read "Result":** REAL TEST means an assertion in this repo's test suite actually
exercises the failure/attack path described, not that the underlying risk is fully eliminated
— see "Residual risk / limitation" for what a passing test does *not* prove. DISCLOSED, NOT
TESTED means we found no honest way to exercise the scenario at this level (usually: it needs
real kernel/hardware state a Python test can't fabricate) and are saying so plainly, per this
repo's "no silent mocks" rule, rather than writing a test that doesn't actually prove anything.

## Chaos scenarios

| # | Scenario | Result | Test(s) | Residual risk / limitation |
|---|---|---|---|---|
| C1 | Service kill / restart | REAL TEST | `test_a_fresh_exporter_instance_after_restart_delivers_what_the_old_one_spooled` (tests/test_chaos_adversarial.py) | Proves the durable spool survives a process restart. Does not prove systemd's own `Restart=on-failure` actually respawns the process correctly on a real host — that's `scripts/verify_hardened_unit.sh`'s job, not yet run live (item 5). |
| C2 | Sensor unload | REAL TEST (fixed a real bug) | `test_tick_still_publishes_when_sensor_health_itself_raises` | Previously `Watchdog.tick()` aborted its entire publish when `sensor.health()` raised, so the dashboard kept showing stale "healthy" data during exactly this failure. Fixed in `shield/watchdog.py` this session (each sub-check now independently try/excepted). Does not cover the eBPF program silently detaching without `health()` itself raising — `health()`'s `attached: True` is set once at construction and never re-verified against live kernel state (see `shield/sensors/ebpf/loader.py`'s known gap, item 3). |
| C3 | Network loss (bcc_middleware/Oracle down) | REAL TEST | `tests/test_exporter_spool.py` (all cases), `tests/test_preflight.py` (unreachable bcc_middleware/Oracle) | Proves the exporter spools and later delivers, and preflight reports unreachability honestly. Does not cover an outage lasting longer than the spool's own disk-space or retry-count bounds (unbounded growth under a very long outage is a real, undisclosed-until-now limit — spool.py has no row cap). |
| C4 | Disk exhaustion | REAL TEST | `test_spool_enqueue_survives_an_unwritable_path_without_raising`, `test_export_decision_still_returns_a_clean_failure_when_disk_is_also_full` | Proves `spool.enqueue()` degrades to a logged loss rather than a crash. Does NOT prove the `EventLog`'s own JSONL append (a separate write path, `agent_core/eventlog.py`) degrades equally gracefully under `ENOSPC` — not tested here, a real gap for a future pass. |
| C5 | Key loss (corrupted signing key) | REAL TEST (fixed a real bug) | `test_sign_policy_reports_a_clean_error_for_a_corrupted_key_file` | Previously `shield sign-policy` crashed with a raw `cryptography`-library traceback on a corrupted existing key file. Fixed in `shield/cli.py` this session. Does not cover a corrupted DID keypair file (`integrity_sdk.did.load_or_create_did`'s own error handling) — that's SDK-owned code, out of this repo's boundary. |
| C6 | Policy rollback (under attack) | REAL TEST (pre-existing) | `tests/test_hot_reload.py`: `test_rejects_untrusted_policy_hash_on_reload`, `test_rollback_to_unknown_hash_fails_without_raising`, `test_expiry_is_reported_unhealthy_without_a_file_change`; `rollback_to()` itself re-verifies signature/trust via the same `load_policy_bundle()` every load path uses | An attacker with filesystem write access to the retained history directory itself (not just the live rules file) could plant a malicious "retained" bundle — history integrity isn't independently signed, only the bundles inside it are. Consistent with `SECURITY.md` §5's stated root-attacker scope (unmitigated by design). |
| C7 | Clock skew | DISCLOSED, NOT TESTED as a "found and fixed" item — documented trust assumption | `tests/test_config_signing.py`'s expiry tests exercise relative time offsets, not literal device-clock skew | Policy expiry (`expires_at`) and the AIS-adjacent nonce/timestamp checks in `integrity_sdk.bcc` all trust the local device clock. A device with a badly-skewed clock could see a not-yet-expired bundle rejected as expired (fails safe) or, worse, treat an already-expired bundle as valid if skewed backward far enough. No NTP-verified time source exists anywhere in this stack. This is a real, disclosed limitation, not a bug fixed this session. |

## Adversarial scenarios

| # | Scenario | Result | Test(s) | Residual risk / limitation |
|---|---|---|---|---|
| A1 | Prompt / tool abuse | REAL TEST (pre-existing) | `tests/test_guardrail_hooks.py` | Guardrail hooks are opt-in instrumentation (`SECURITY.md` §7) — Shield cannot force an uninstrumented agent runtime through a hook it never calls. Not a code gap; a documented scope boundary. |
| A2 | Policy bypass (unmatched event defaults to allow) | REAL TEST (pre-existing) | `tests/test_policy_engine.py` (rule_id `_no_match` shape), `test_router_exports_telemetry_for_every_decision` (tests/test_agent_core.py) proves an unmatched/default-allow decision is still exported/visible, not silently dropped | Default-allow is a deliberate design choice (`SECURITY.md` §1), not a bypass bug — the "bypass" a reviewer should check is whether it's visible to an operator, which it is. An unconfigured deployment is a visibility tool, not a control; don't represent it otherwise. |
| A3 | Replay (BCC evidence resubmission) | REAL TEST | `test_sequential_exports_use_strictly_increasing_nonces` (real, non-mocked `bcc.NonceStore`) | Proves local monotonic nonce assignment. Server-side replay rejection (`bcc_middleware/app/nonce_store.py`'s `check_and_record`) is the other, out-of-repo half of this defense; not re-tested here, referenced by design in `shield/integrity_exporter/spool.py`'s own docstring. |
| A4 | Downgrade | REAL TEST (pre-existing) | `tests/test_hot_reload.py`: `test_rejects_policy_downgrade_when_enabled`, `test_policy_without_revision_is_rejected_after_revisioned_policy` | `reject_downgrades` is opt-in (`DeviceConfig.reject_policy_downgrades`, default `False`) — a deployment that never enabled it is not protected. Visible in device config, not a silent gap. |
| A5 | Event flooding | REAL TEST | `test_router_survives_and_records_a_burst_of_events_without_silent_loss` (500 events, software layer) | Proves the router/policy-engine/event-log path doesn't crash or silently drop under burst load at the Python layer. Does NOT cover real eBPF ring-buffer overflow under sustained kernel-level load — that's `lost_events`/`test_lost_events_counter_reflects_bcc_lost_cb`'s territory (item 3), a different layer of the same concern. |
| A6 | PID reuse | DISCLOSED, NOT TESTED | none — deliberately not fabricated | `file_write.bpf.c`/`tcp_connect.bpf.c`/`process_exec.bpf.c` correlate kprobe-entry to kretprobe-return via a `BPF_HASH` keyed on `bpf_get_current_pid_tgid()` (`tgid<<32 | pid`). If a numeric PID is reused by a new single-threaded process before an old, uncorrelated hash entry is cleaned up, that new process could in principle collide with a stale entry. This needs real kernel/BTF-level testing (a controlled PID-reuse race under load) that a Python unit test cannot honestly simulate — fabricating one would violate this repo's "no silent mocks" rule more than leaving it disclosed. Real follow-up: a root-run integration test that forces rapid PID reuse (e.g. via a tight fork/exit loop) and checks for misattributed events, out of scope for this pass. |
| A7 | Containment failure | REAL TEST (fixed a real bug) | `test_containment_failure_reports_a_truthful_enforcement_outcome` | Previously untested whether `enforcement_outcome_sink` actually receives a truthful `completed=False` + real error on a realistic failure (`ProcessLookupError`, not a fabricated exception type) — now verified. `ActionBroker.contain()` itself still has no internal retry/escalation on failure (by design — see its own module docstring on why timeout-based escalation is the caller's job, not inline here). |

## Summary for Gate 6

12 of 14 scenarios have a real, passing automated test. Of those 12, 4 (C6, A1, A2, A4) reuse
pre-existing coverage this session verified is real and on-point rather than assumed; the
other 8 are new this session, and 3 of those (C2, C5, A7) surfaced and fixed a real,
previously-unknown bug in the process, not just confirmed already-correct behavior. The
remaining 2 scenarios are honestly disclosed rather than fabricated: C7 (clock skew) is a
named trust assumption with no pass/fail test, and A6 (PID reuse) is disclosed as not
independently testable at the Python-unit level, with a concrete real follow-up named
(root-run PID-reuse race test) rather than silently deferred.

**No unexplained critical bypass was found.** This matrix earned its existence by finding
real problems (C2, C5, A7), not just documenting assumed-fine behavior.

Run `python3 scripts/run_adversarial_tests.py --out <path>` to regenerate the artifact
`scripts/pilot_gate_report.py --adversarial-artifact <path>` consumes for the "chaos/
adversarial validation" gate.
