# Linux Agent Runbook

This runbook turns the existing `shield run` loop into a supervised Linux process. It does not remove the remaining pilot blockers: TCP-connect still needs root verification on every supported target kernel, and live Integrity exporter identity still needs funded registration/readback validation.

## Install

The backend automatically creates a persistent cryptographic super-admin token
at `~/.xibalba-shield/backend-admin.token` (mode `0600`) when neither
`SHIELD_BACKEND_TOKEN` nor `--admin-token` is supplied. It reuses that token on
restart and never prints its value. For tenant operator access, use
`scripts/rotate_tenant_admin_token.sh`; do not copy the global token into a
browser profile.

For local UI development, Vite reads the tenant token server-side from
`~/.xibalba-shield/<tenant>-admin-token` and exposes a one-click **Connect to
local Shield** action. The browser stores only a non-secret proxy marker; Vite
adds the real authorization header while forwarding `/api` requests. Override
the tenant or file with `SHIELD_DEV_TENANT` and
`SHIELD_DEV_ADMIN_TOKEN_FILE`. This helper does not exist in production builds.

1. Build and install the package in the target Python environment:

   ```bash
   python3 -m pip install .
   ```

2. Create the dedicated `xibalba-shield` system account the hardened unit runs as
   (`packaging/systemd/xibalba-shield.service`'s `User=`/`Group=`, 2026-09-05) and local
   config directories owned by it -- `scripts/install_linux_agent.sh` does both of these
   steps for you; shown here manually for a from-scratch walkthrough:

   ```bash
   sudo groupadd --system xibalba-shield
   sudo useradd --system --gid xibalba-shield --no-create-home --shell /usr/sbin/nologin xibalba-shield
   sudo install -d -m 0750 -o xibalba-shield -g xibalba-shield /etc/xibalba-shield/policies /var/log/xibalba-shield /var/lib/xibalba-shield
   ```

   Any file you create under `/etc/xibalba-shield` yourself in the steps below (device
   config, policy bundle) must also be owned by `xibalba-shield:xibalba-shield` (or at least
   group-readable by it) -- the unit no longer runs as root and cannot read a root-only file.

3. Install a device config at `/etc/xibalba-shield/device.json`:

   ```json
   {
     "device_id": "pilot-linux-001",
     "tenant_id": "tenant-001",
     "device_role": "workstation",
     "bcc_middleware_url": "http://localhost:8000",
     "tenant_policy_url": "",
     "device_token": "",
     "sensitive_paths": ["/home/*/.ssh/*", "/etc/*", "/var/secrets/*"],
     "trusted_policy_hashes": []
   }
   ```

4. Install a default policy pack as `/etc/xibalba-shield/policies/current.json` and validate it:

   ```bash
   shield validate --device-config /etc/xibalba-shield/device.json --rules /etc/xibalba-shield/policies/current.json
   ```

   For stricter pilots, copy the `policy_hash` printed by `shield validate --rules ...` into
   `trusted_policy_hashes`. `shield run` and hot reload will then reject any bundle whose
   exact-file hash is not pinned.

   To fetch from a tenant policy endpoint instead:

   ```bash
   shield fetch-policy --device-config /etc/xibalba-shield/device.json --output /etc/xibalba-shield/policies/current.json
   ```

   Fix ownership of whatever you just created, since the unit reads these as `xibalba-shield`, not root:

   ```bash
   sudo chown -R xibalba-shield:xibalba-shield /etc/xibalba-shield
   ```

5. Install and start the systemd unit:

   ```bash
   sudo cp packaging/systemd/xibalba-shield.service /etc/systemd/system/xibalba-shield.service
   sudo cp packaging/systemd/shield.env.example /etc/xibalba-shield/shield.env
   sudo systemctl daemon-reload
   sudo systemctl enable --now xibalba-shield
   ```

   By default this unit assumes OPA is already running as an externally managed sidecar
   at the policy engine's `--opa-url` (default `http://localhost:8181`) — this package
   does not install or manage an OPA process for you. To have Shield itself own the OPA
   process lifecycle instead (start it, actively health-probe it, and restart it with
   bounded backoff on failure via `OpaSupervisor`), install an `opa` binary on this host
   first, then set `SHIELD_OPA_ARGS` in `/etc/xibalba-shield/shield.env`:

   ```bash
   sudo sed -i \
     's#^SHIELD_OPA_ARGS=.*#SHIELD_OPA_ARGS=--opa-command /usr/local/bin/opa run --server --addr localhost:8181#' \
     /etc/xibalba-shield/shield.env
   sudo systemctl restart xibalba-shield
   ```

   `SHIELD_OPA_ARGS` must carry the whole `--opa-command ...` flag, not just a bare path
   — the CLI flag takes one-or-more arguments (`nargs="+"`), so it cannot be left in the
   unit's fixed `ExecStart` line with nothing following it when this is unset, the same
   reason `SHIELD_EXPORTER_ARGS` carries its whole flag rather than just a value.

### Local mTLS control plane and split helper

For local development, the backend can expose a dedicated mTLS listener on
`https://127.0.0.1:8443`. The HTTP listener on `127.0.0.1:8421` remains useful for the
operator UI and authenticated readback. The local CA is not a production trust root.

Generate the local-only credentials and install the helper's client credentials:

```bash
./scripts/generate_local_mtls_ca.sh
./scripts/repair_device_config_tls.sh
```

The repair script updates `/etc/xibalba-shield/device.json` with the HTTPS backend URL,
CA bundle, client certificate, and client key, then restarts the endpoint. It preserves
the device token and policy settings. The remediation worker, runtime-status publisher,
and policy distributor all use the same verified TLS client context; a TLS handshake
failure must not be worked around by disabling certificate verification.

The privileged helper owns the BCC/eBPF capabilities and `/run/xibalba-shield/ebpf.sock`;
the endpoint runs as `xibalba-shield` and consumes that socket. Keep the unit relationship
intact:

```bash
sudo systemctl enable --now xibalba-shield-ebpf-helper.service
sudo systemctl enable --now xibalba-shield.service
systemctl is-active xibalba-shield-ebpf-helper.service xibalba-shield.service
```

Only the helper declares `RuntimeDirectory=xibalba-shield`. The endpoint requires and starts
after the helper but must not declare the same runtime directory: systemd can remove a shared
runtime directory during an endpoint restart while the helper is still listening on an orphaned
file descriptor. If the socket disappears, reload the units and restart the helper before the
endpoint:

```bash
sudo systemctl daemon-reload
sudo systemctl restart xibalba-shield-ebpf-helper.service
sudo systemctl restart xibalba-shield.service
```

Validate transport and live telemetry through the authenticated backend status endpoint:

```bash
token_file="$HOME/.xibalba-shield/tenant-a-admin-token"
token="$(< "$token_file")"
curl -fsS -H "Authorization: Bearer ${token}" \
  'http://127.0.0.1:8421/api/shield/exporter-status?tenant_id=tenant-a'
unset token
```

The current local verification reached `sensors.attached=true`, observed real process events,
reported `lost_events=0`, and showed OPA healthy and zero exporter failures. Do not treat those
local values as multi-kernel or production deployment qualification.

## Diagnose

Use local-only mode until the Integrity exporter DID is registered:

```bash
sudo sed -i 's/^SHIELD_EXPORTER_ARGS=.*/SHIELD_EXPORTER_ARGS=--no-exporter/' /etc/xibalba-shield/shield.env
sudo systemctl restart xibalba-shield
```

Inspect runtime state:

```bash
systemctl status xibalba-shield
journalctl -u xibalba-shield -n 100 --no-pager
shield --log-path /var/log/xibalba-shield/decisions.jsonl status
shield --log-path /var/log/xibalba-shield/decisions.jsonl events --recent 20
```

`shield status`/`events` only reflect the local decision log. Fleet-level OPA/policy/
sensor/exporter health — including sensor `lost_events` and exporter `queue_depth`, both
published every `--watchdog-interval` seconds (default 15s) independent of whether any
events are actually flowing — is visible on the dashboard's Shield fleet view or via the
backend's `GET /api/shield/exporter-status` endpoint, not this CLI.

If the service was started with `--log-integrity-key /var/lib/xibalba-shield/log.key`, verify local log continuity:

```bash
shield --log-path /var/log/xibalba-shield/decisions.jsonl verify-log --integrity-key /var/lib/xibalba-shield/log.key
```

Export to SIEM/SOAR:

```bash
shield --log-path /var/log/xibalba-shield/decisions.jsonl siem-export --output /var/log/xibalba-shield/siem.jsonl
shield --log-path /var/log/xibalba-shield/decisions.jsonl siem-export --webhook-url https://soar.example.com/xibalba-shield
```

Run a root-free synthetic smoke test:

```bash
shield --log-path /tmp/shield-decisions.jsonl run --sensor dev --device-id smoke --rules policies/defaults/smb.json --no-exporter --max-events 10 --dev-interval 0
```

Run the repeatable validation harness:

```bash
.venv/bin/python scripts/e2e_validate.py
```

The harness reports missing root or missing live Integrity services as skipped checks. Use
`sudo .venv/bin/python scripts/e2e_validate.py` for real eBPF probe verification, and set
`BCC_MIDDLEWARE_URL` or `--bcc-url` when validating against a live Integrity stack.

Preflight the live Integrity registration/readback environment:

```bash
.venv/bin/python scripts/did_env_preflight.py
RPC_URL=http://127.0.0.1:8545 \
DEPLOYMENTS_FILE=/home/xibalba/Projects/integrity-core/deployments.local.json \
.venv/bin/python scripts/verify_oracle_registration.py
```

For a local Anvil-only registration/readback closure when `oracle-backend` is not running:

```bash
FUNDER_PRIVATE_KEY=<funded-local-anvil-private-key> \
INTEGRITY_WALLET_PASSWORD="$(cat /home/xibalba/.integrity/wallet/xibalba-shield/WALLET_PASSWORD.txt)" \
.venv/bin/python scripts/register_with_oracle.py --skip-oracle-registration
.venv/bin/python scripts/verify_oracle_registration.py
```

Run a burn-in snapshot:

```bash
python3 scripts/burn_in.py --duration-sec 3600 --output /var/log/xibalba-shield/burn-in.json
```

False-positive rates require operator review labels. Supply one JSON object per reviewed decision:

```bash
printf '{"decision_id":"row-1","false_positive":false}\n' > /tmp/shield-fp-labels.jsonl
python3 scripts/burn_in.py \
  --duration-sec 3600 \
  --false-positive-labels /tmp/shield-fp-labels.jsonl \
  --output /var/log/xibalba-shield/burn-in.json
```

Run TCP-connect verification only on the target kernel with root:

```bash
python3 scripts/verify_tcp_connect_root.py   # reports blocked unless run as root
sudo python3 scripts/verify_tcp_connect_root.py > /var/log/xibalba-shield/tcp-connect-root.json
```

Summarize pilot gates from real artifacts:

```bash
python3 scripts/pilot_gate_report.py \
  --tcp-artifact /var/log/xibalba-shield/tcp-connect-root.json \
  --did-artifact /var/log/xibalba-shield/did-readback.json \
  --burn-in-artifact /var/log/xibalba-shield/burn-in.json \
  --hardening-attestation /var/log/xibalba-shield/os-hardening-attestation.txt \
  --installer-attestation /var/log/xibalba-shield/installer-attestation.txt
```

For Linux-only pilots, omit Windows/macOS artifacts and keep those gates explicitly blocked. A customer-grade release must include `artifact_sha256`, `signature`, `service_manager`, and `rollback` in the installer attestation. Root/admin resistance requires an OS-level hardening attestation covering `secure_boot`, `tpm_or_mdm`, `service_protection`, and `log_key_protection`; local HMAC logs alone are not root-proof.

## Rollback

Policy rollback is file-based:

```bash
sudo cp /etc/xibalba-shield/policies/previous.json /etc/xibalba-shield/policies/current.json
shield validate --rules /etc/xibalba-shield/policies/current.json
sudo systemctl restart xibalba-shield
```

Binary/package rollback (2026-09-05): `shield/release/` + `scripts/release_manager.py`
now give a real, signed, versioned mechanism instead of "reinstall the previous reviewed
wheel or commit" -- `install` verifies a signed wheel (`scripts/sign_release.py`) before
creating a new, independent `<releases-dir>/<version>/` and only then atomically flips
`<current-link>`; `rollback` flips it back to an already-installed version with no
reinstall, no network call, and no re-verification (the release was verified once, at
install time):

```bash
# One-time: create a release-signing keypair (separate from the policy-signing key) and
# sign a built wheel.
python3 scripts/sign_release.py --key ~/.xibalba-shield/release-signing.key \
    --wheel dist/xibalba_shield-0.1.1-py3-none-any.whl \
    --out dist/xibalba_shield-0.1.1.attestation.json

# Install the new signed release (verifies before touching anything, then swaps `current`):
sudo python3 scripts/release_manager.py install \
    --wheel dist/xibalba_shield-0.1.1-py3-none-any.whl \
    --attestation dist/xibalba_shield-0.1.1.attestation.json \
    --version 0.1.1 --releases-dir /opt/xibalba-shield/releases \
    --current-link /opt/xibalba-shield/current
sudo systemctl restart xibalba-shield

# Rollback -- a symlink flip, not a reinstall:
sudo python3 scripts/release_manager.py rollback --version 0.1.0 \
    --releases-dir /opt/xibalba-shield/releases --current-link /opt/xibalba-shield/current
sudo systemctl restart xibalba-shield
```

**Not yet wired to a live install**: `packaging/systemd/xibalba-shield.service`'s
`ExecStart` still hardcodes `/usr/local/bin/shield` (from a plain `pip install .`), not
`<current-link>/bin/shield` -- pointing the unit at the versioned-release path is a
separate, deliberate change (it alters the real deployment path for every existing
install) not made alongside this mechanism's introduction. Until that's done, the tools
above exist and are tested but aren't yet the live upgrade path `install_linux_agent.sh`
uses.

## Uninstall

```bash
sudo systemctl disable --now xibalba-shield
sudo rm -f /etc/systemd/system/xibalba-shield.service
sudo systemctl daemon-reload
python3 -m pip uninstall xibalba-shield
```

Remove `/etc/xibalba-shield`, `/var/log/xibalba-shield`, and `/var/lib/xibalba-shield` only after exporting or preserving local decision logs needed for incident review.
### Proving and enabling gated responders

`freeze_cgroup`, `kill_process`, and `block_flow` are fail-closed. An enable
flag alone is insufficient: the agent also requires a fresh proof artifact
bound to its device ID. On the deployment host, run the disposable probe as
root and provide a non-empty evidence reference for each base proof:

```bash
sudo uv run python scripts/verify_responder_gates.py \
  --device-id DEVICE_ID \
  --output /etc/xibalba-shield/responder-readiness.json \
  --base-proof policy_signature_verified=POLICY_BUNDLE_HASH \
  --base-proof agent_identity_verified=ENROLLMENT_RECORD_ID \
  --base-proof kernel_probe_verified=LIVE_GATE_ARTIFACT \
  --base-proof audit_receipt_verified=RECEIPT_ID \
  --base-proof rollback_verified=ROLLBACK_TEST_ID \
  --base-proof operator_approval=CHANGE_REQUEST_ID
```

The runner writes a root-owned, service-group-readable (`0640`) artifact, kills
only a disposable `sleep`, freezes and resumes only its own
temporary cgroup, and creates then deletes a uniquely named nftables table.
After reviewing the JSON, configure:

```bash
SHIELD_RESPONDER_ARGS=--responder-readiness /etc/xibalba-shield/responder-readiness.json --enable-kill-process --enable-freeze-cgroup --enable-block-flow
```

Proof artifacts expire after 24 hours by default. The live agent report exposes
effective capabilities and missing proofs; the UI cannot override either gate.
