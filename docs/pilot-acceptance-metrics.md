# Pilot Acceptance Metrics

Status: v1 pilot gate definition.

Shield is pilot-ready for a Linux endpoint cohort only when these metrics are measured on the target pilot environment and recorded in the audit ledger.

## Resource Use

- Idle CPU: <= 1% over a 30-minute window.
- Sustained CPU under normal endpoint activity: <= 5% over a 30-minute window.
- Peak resident memory: <= 90 MB for the Shield process.
- No unbounded local log growth without operator-configured rotation.

Measure with `scripts/measure_resource_budget.py` for synthetic/dev paths and a separate root-run measurement for real `process-exec` and `file-write` sensors.

## Sensor Coverage

- Process-exec sensor observes a real spawned process on every pilot kernel.
- File-write sensor observes a real write-open on every pilot kernel.
- Sensitive-path filtering only emits configured sensitive path matches during pilot validation.
- TCP-connect is either verified on the pilot kernel stack or removed from pilot claims.

## Policy Behavior

- `shield validate` passes for the deployed device config and policy bundle.
- If `trusted_policy_hashes` is configured, startup rejects an unpinned bundle.
- Hot reload accepts a valid trusted bundle and keeps last-known-good rules for malformed or untrusted edits.
- Default allow, deny, contain, log-only, and escalate decisions are visible in the local JSONL log.

## False Positives

- Every deny/contain/escalate event in the pilot sample is reviewable by rule ID and reason.
- False-positive rate for blocking decisions is <= 5% over the pilot window, unless the operator explicitly chooses a stricter regulated policy pack.
- Any false positive that blocks a normal workflow has a documented policy change, scope adjustment, or accepted-risk decision before pilot expansion.

## Detection Quality

- Shield ADR (Attack Detection Rate) is measured as `true_positive_security_decisions /
  labeled_malicious_events`.
- A true positive is a labeled malicious event where Shield returned `deny`, `contain`, or a
  justified `escalate`.
- Pilot ADR claims require labeled pilot-window, benchmark, or red-team events; synthetic events
  may validate wiring only and must be reported separately.
- Precision is measured as `true_positive_security_decisions /
  all_deny_contain_escalate_decisions`.
- Mean time to contain is measured for contained malicious events as
  `containment_timestamp - first_observed_timestamp`.
- Every detection-quality metric is reproducible from event ID, device ID, tenant ID, policy
  version/hash, decision action, rule ID, export status, Integrity receipt when available, label,
  and label source.
- Receipt-backed Shield ADR requires `POST /api/shield/detection-quality/report` to verify every
  ADR-counted security decision through BCC middleware `/v1/bcc/verify_token`; Oracle audit-log
  readback must be checked when the pilot has an Oracle URL.

## Export Success

- Exporter DID is registered with Integrity Oracle.
- At least 99% of policy decisions export successfully during a normal pilot day.
- `shield events --recent` exposes export failures as `export=failed`.
- Exported decisions are queryable through the intended Integrity evidence/audit surface.

## Operator Usability

- An operator can install, start, inspect, restart, roll back policy, and uninstall using `docs/runbooks/linux-agent.md`.
- `shield status` returns a useful local decision count without external services.
- `shield events --recent 20` shows action, rule, and export state without requiring raw log parsing.
- Any expected operational failure, including non-root eBPF startup, exits cleanly without a traceback.

## Evidence Artifacts

Archive real target evidence before moving a gate from blocked to passed:

- TCP-connect eBPF: JSON output from `sudo python3 scripts/verify_tcp_connect_root.py` on each target kernel.
- Live DID path: JSON readback from `scripts/verify_oracle_registration.py` against reachable RPC and Oracle deployment credentials.
- Windows/macOS native sensors: platform-native validation JSON from the target OS, not Linux placeholders.
- Burn-in: `scripts/burn_in.py` JSON plus operator false-positive review labels over at least 48 hours unless a pilot plan specifies a longer window.
- Detection quality: labeled event corpus or review export containing label, label source,
  event ID, policy hash, decision action, BCC verification token status, Oracle audit-log
  readback status, and Integrity receipt/readback status for every event counted in Shield ADR
  or precision.
- Installer/updater: attestation with `artifact_sha256`, `signature`, `service_manager`, and `rollback`.
- Root/admin resistance: attestation with `secure_boot`, `tpm_or_mdm`, `service_protection`, and `log_key_protection`.

`scripts/pilot_gate_report.py` summarizes these artifacts. Missing artifacts remain `BLOCKED`; invalid artifacts fail the report.

## Exit Criteria

A pilot cohort passes only if every non-blocked metric above is met and every blocked metric is explicitly listed in the final pilot report with owner, reason, and next verification step.
