# Network Shield deployment boundary

Network Shield is not deployed to a gateway, DNS resolver, firewall, NAC controller, switch, or
Wi-Fi controller by default. The current host has only endpoint-local observation and a local
resolver stub; no authoritative network controller API has been verified.

Verify deployment provenance separately from a successful HTTP probe:

```bash
./scripts/verify_backend_service_boundary.sh
```

The Linux installer now places `xibalba-shield-backend.service` with the other managed unit
files, but backend enablement is opt-in (`ENABLE_BACKEND_SERVICE=1`). This prevents an agent
upgrade from silently taking ownership of an already-running backend. After an operator-approved
handoff, enable the unit and reload systemd before validating ownership.

The verifier is read-only and reports drift when a manually launched backend owns port 8421 while
`xibalba-shield-backend.service` is inactive. A healthy response from that port is not proof that
the installed systemd unit is serving the request.

After confirming the PID and accepting the brief local control-plane interruption, an operator may
run the guarded handoff:

```bash
sudo ./scripts/handoff_backend_to_systemd.sh --takeover
```

Without `--takeover` the script only verifies the exact backend command and exits without changing
process or service state. It never escalates a graceful stop to `SIGKILL`.

Before a production adapter is enabled:

1. Identify the authorized device/API and record its owner, scope, authentication method, and
   supported rollback operation.
2. Create a disposable lab segment and verify the adapter against that segment only.
3. Use a dedicated service identity with the minimum action scope; never give Hermes root,
   router-admin, unrestricted nftables, SSH, or arbitrary controller access.
4. Configure protected management, identity, DNS, Shield, Hermes, backend, and recovery paths.
5. Set device/segment blast-radius caps, bounded duration, canary scope, and automatic rollback.
6. Require operator approval for segment-wide or network-wide actions.
7. Verify adapter acknowledgement and audit records before describing an action as completed.

Hermes and Cortex are downstream consumers. Local policy and the local enforcement point remain
authoritative during cloud, Hermes, Cortex, identity-provider, or adapter outages.

For the Shield Hermes profile, use Settings → Hermes Agent to set the tenant-scoped delivery
controls. Reconcile `SHIELD_HERMES_SPOOL` and `SHIELD_HERMES_KEY` on the host separately; the UI
stores paths as configuration metadata but never provisions or rotates the HMAC key. Verify the
authenticated `GET /api/shield/hermes-status` response after restart and confirm pending,
acknowledged, and dead-letter counters before treating delivery as healthy.
