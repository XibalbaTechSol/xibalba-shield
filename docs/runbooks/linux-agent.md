# Linux Agent Runbook

This runbook turns the existing `shield run` loop into a supervised Linux process. It does not remove the remaining pilot blockers: TCP-connect is still unverified on the current BCC/kernel stack, and live Integrity exporter identity still needs oracle registration.

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
     "sensitive_paths": ["/home/*/.ssh/*", "/etc/*", "/var/secrets/*"]
   }
   ```

4. Install a default policy pack as `/etc/xibalba-shield/policies/current.json` and validate it:

   ```bash
   shield validate --device-config /etc/xibalba-shield/device.json --rules /etc/xibalba-shield/policies/current.json
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

Run a root-free synthetic smoke test:

```bash
shield --log-path /tmp/shield-decisions.jsonl run --sensor dev --device-id smoke --rules policies/defaults/smb.json --no-exporter --max-events 10 --dev-interval 0
```

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
