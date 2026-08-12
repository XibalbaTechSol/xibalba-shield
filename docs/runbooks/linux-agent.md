# Linux Agent Runbook

This runbook turns the existing `shield run` loop into a supervised Linux process. It does not remove the remaining pilot blockers: TCP-connect still needs root verification on the target kernel, and live Integrity exporter identity still needs funded registration/readback validation.

## Install

1. Build and install the package in the target Python environment:

   ```bash
   python3 -m pip install .
   ```

2. Create local config directories:

   ```bash
   sudo install -d -m 0750 /etc/xibalba-shield/policies /var/log/xibalba-shield /var/lib/xibalba-shield
   ```

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

5. Install and start the systemd unit:

   ```bash
   sudo cp packaging/systemd/xibalba-shield.service /etc/systemd/system/xibalba-shield.service
   sudo cp packaging/systemd/shield.env.example /etc/xibalba-shield/shield.env
   sudo systemctl daemon-reload
   sudo systemctl enable --now xibalba-shield
   ```

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

Binary rollback is package-manager specific. The minimum safe rollback is to reinstall the previous reviewed wheel or commit, then restart the service. Do not replace binaries from an unsigned download.

## Uninstall

```bash
sudo systemctl disable --now xibalba-shield
sudo rm -f /etc/systemd/system/xibalba-shield.service
sudo systemctl daemon-reload
python3 -m pip uninstall xibalba-shield
```

Remove `/etc/xibalba-shield`, `/var/log/xibalba-shield`, and `/var/lib/xibalba-shield` only after exporting or preserving local decision logs needed for incident review.
