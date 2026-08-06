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

## Exit Criteria

A pilot cohort passes only if every non-blocked metric above is met and every blocked metric is explicitly listed in the final pilot report with owner, reason, and next verification step.
