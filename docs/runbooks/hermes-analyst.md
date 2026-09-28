# Runbook: Shield Hermes analyst

The Shield Hermes analyst gives Shield's agent a bounded, **analysis-only** judgment step over
its own material events. Shield's DID is the Hermes `xibalba-shield` agent, and the sensor is
that agent's body.

Code: `shield/hermes_analyst.py`. Unit: `packaging/systemd/shield-hermes-analyst.service`.
Profiles: `packaging/hermes/`. Deployed 2026-09-27 in **shadow mode**: analyses are recorded
and nobody is notified.

## Data flow

```
sensor (xibalba-shield) --contain/deny/escalate--> HermesSpool (HMAC, bounded)
  /var/lib/xibalba-shield/hermes-spool (2770, group xibalba-shield)
      |
shield-hermes-analyst (system unit: User=xibalba, SupplementaryGroups=xibalba-shield,
                       key via LoadCredential)
  materiality -> 24 h dedupe -> budget (6/h, 40/day) -> allowlisted, fenced DATA prompt
  -> hermes -p xibalba-shield-analyst -z   (toolless, memory off, scrubbed env)
  -> strict advisory validation (enum recommendation, no command keys, api_calls == 1)
  -> ledger /var/lib/shield-hermes-analyst/ledger.sqlite3
  -> one Cortex memory (kind shield_advisory, evidence_class inference) as Shield's DID
     carrying classification, confidence, evidence_refs and recommendation only
  -> optional templated notification (off until P2)
```

## Invariants

- **Enforcement never depends on the analyst.** The sensor contains first and publishes
  afterwards. Bad Hermes configuration disables publication with a warning and never stops
  the sensor.
- **Telemetry is data.** The model sees an allowlisted, redacted view inside a
  `<<<SHIELD_EVENT_DATA … SHIELD_EVENT_DATA>>>` fence. Fence markers and control characters
  are stripped from event strings.
- **No tools.** `--preflight` builds the same `AIAgent` that `hermes -z` builds and counts the
  tool schemas it would send. Any tool, MCP server, plugin, hook, or enabled memory fails
  closed, and events are ledgered as `preflight_failed`. A run with more than one API call, or
  with no usage report, is discarded.
- **No model free text leaves the ledger.** Neither Cortex nor notifications receive
  `uncertainty` or any other prose from the model.
- **The HMAC key is never readable by interactive shells.** `xibalba` is not a member of
  `xibalba-shield`; only the unit gets the group.

## Operate

```bash
# Status: outcomes, spend, Cortex delivery (last 24 h)
/opt/xibalba-shield/venv/bin/python -c "import sqlite3;print(sqlite3.connect('file:/var/lib/shield-hermes-analyst/ledger.sqlite3?mode=ro',uri=True).execute('select outcome,cortex_status,count(*) from analyses group by 1,2').fetchall())"
journalctl -u shield-hermes-analyst.service -n 50

# Prove the analyst profile is toolless (no model call)
/opt/xibalba-shield/venv/bin/python -m shield.hermes_analyst --preflight
```

Ledger outcomes:

| Outcome | Meaning |
|---|---|
| `analysed` | A valid advisory was recorded. |
| `skipped_not_material` | The event was not contain, deny, or escalate. |
| `dedup` | Same rule, executable, and parent seen within 24 h. |
| `unanalysed_budget` | The hourly or daily cap was reached. |
| `preflight_failed` | The profile is not provably toolless. |
| `model_failed` / `model_invalid` | The call failed, or the reply was not a valid advisory. |
| `internal_error` | Supervisor bug; the handler never raises. |

## Install, redeploy, roll back

Run the installer from a clean `main` checkout, with sudo. It is staged, stops at the first
failure, and rolls back the sensor step automatically:

```bash
sudo scripts/install_hermes_analyst.sh
```

Step 3 preflights the spool **inside the sensor unit's real sandbox** with `systemd-run`.
Earlier attempts used `runuser` and missed a `RestrictSUIDSGID` EPERM. The installer finishes
with a signed prompt-injection canary. `canary-*` events are analysed but never written to
Cortex.

Rollback:

```bash
systemctl disable --now shield-hermes-analyst.service
rm /etc/systemd/system/shield-hermes-analyst.service /etc/systemd/system/xibalba-shield.service.d/hermes.conf
systemctl daemon-reload && systemctl restart xibalba-shield.service
```

## Deploy lessons (2026-09-27)

- `/opt/xibalba-shield/venv` is updated with `--no-deps`, so it drifted from `uv.lock`.
  `scripts/sync_production_venv.sh` brings it back, with a snapshot and rollback. The deploy
  script refuses to install onto a drifted venv.
- Runtime data files must be listed in `package-data`; `tests/test_packaging.py` enforces
  this.
- The sensor unit sets `RestrictSUIDSGID=true`, so the spool never chmods a setgid bit it
  already has.

## Enable notifications (P2, after the 48 h shadow review)

Set the delivery target in a drop-in and restart. A notification is a fixed template of
validated fields, rate-limited to one every 15 minutes, with a digest of the rest.

```ini
# /etc/systemd/system/shield-hermes-analyst.service.d/notify.conf
[Service]
Environment=SHIELD_ANALYST_NOTIFY_TARGET=<platform>
```

Not built yet: the "still frozen after 10 minutes" trigger. It needs the Shield backend on
port 8435.
