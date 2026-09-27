# Shield UI/Hermes configuration handoff

Date: 2026-09-23
Repository: `/home/xibalba/Projects/xibalba-shield`
Branch: `main`

## Completed in this pass

- Added a dedicated `Hermes Agent` tab under Shield Settings.
- Added tenant-scoped Hermes profile controls for:
  - enable/disable delivery;
  - Hermes agent identity;
  - bounded event scope (`all`, `decisions`, or `network`);
  - local authenticated spool transport;
  - strict redaction mode;
  - immutable analysis-only boundary;
  - host spool and HMAC key paths;
  - maximum batch size;
  - bounded spool ceiling;
  - transient-delivery retry preference.
- Added explicit UI evidence that Shield remains the local policy/enforcement authority.
- Added host-managed warnings so the browser does not imply that saving tenant settings mutates the installed service or exposes key material.
- Added authenticated read-only `GET /api/shield/hermes-status` reporting local spool health, pending bytes, acknowledgements, and dead letters without initializing the spool.
- Wired enrolled-agent startup to consume the validated tenant Hermes profile for enablement, event scope, batch size, and spool ceiling; host paths and key material remain environment-managed.
- Reworked the Overview command center with an evidence-backed readiness map and explicit operator next actions.
- Extended backend tenant-settings validation with Hermes-specific bounds and fail-closed validation for `hermesAnalysisOnly`.
- Added focused validation coverage for valid and invalid Hermes settings.
- Extended the mocked Playwright runtime-health journey to cover the Hermes status signal and Hermes settings tab; execution remains deferred with browser validation.
- The mocked journey now also covers an invalid batch validation response, successful save feedback, and a 390px responsive render assertion; Playwright test discovery passes.
- Corrected `scripts/handoff_backend_to_systemd.sh` so its default mode cannot start systemd when no listener is visible; `--takeover` is now required for every mutating path.

## Files changed for the Hermes/UI work

- `ui/src/components/HermesAgentView.jsx`
- `ui/src/components/SettingsView.jsx`
- `ui/src/App.css`
- `shield/backend/settings.py`
- `shield/backend/api.py`
- `shield/hermes_transport.py`
- `shield/cli.py`
- `tests/test_settings_control.py`
- `tests/test_hermes_transport.py`
- `ui/src/components/Overview.jsx`
- `ui/src/api.js`
- `scripts/handoff_backend_to_systemd.sh`

## Verification completed

- `npm run build` in `ui/`: passed.
- `npm run lint` in `ui/`: passed with pre-existing warnings in `Dashboard.jsx` and `AgentView.jsx`.
- `./.venv/bin/pytest -q tests/test_hermes_transport.py tests/test_settings_control.py tests/test_backend.py -k 'hermes or settings_validation'`: `7 passed, 41 deselected`.
- `npx playwright test e2e/runtime-health.spec.ts --list`: passed; browser execution remains intentionally skipped.
- `python3 -m py_compile shield/hermes_transport.py shield/backend/api.py shield/cli.py`: passed.
- `bash -n scripts/handoff_backend_to_systemd.sh`: passed.
- `git diff --check`: passed.
- Handoff script dry run now refuses to start the service and exits with code `4`.

## Browser validation status

Browser validation was intentionally skipped at the user's request for this restart handoff.

Attempts were blocked by the current environment:

- Browser plugin became unavailable during the run.
- Normal Playwright execution could not reach the escalated localhost Vite process.
- Host backend rejected the available development fixture session with `invalid admin token` / `invalid email or password`.

Do not describe the Hermes tab as browser-verified until an authenticated local session is available after restart.

## Important architecture boundary

The UI stores a validated tenant Hermes profile. The enrolled runtime now consumes safe bounded
profile fields at startup and on watchdog refresh; it does not directly write `/etc/xibalba-shield`,
create or rotate HMAC key material, restart the agent, or take ownership of an unmanaged backend.
The transport paths remain host environment variables:

- `SHIELD_HERMES_SPOOL`
- `SHIELD_HERMES_KEY`
- `XIBALBA_SHIELD_HERMES_AGENT_ID`

After restart, reconcile the saved tenant profile with the host service environment and deployment path. If full runtime application from the UI is required, implement an authenticated, host-local configuration reconciler with explicit approval and restart semantics; do not make the browser write secrets or invoke arbitrary shell commands.

## Resume sequence after PC restart

1. Inspect repository state and preserve unrelated dirty work:

   ```bash
   cd /home/xibalba/Projects/xibalba-shield
   git status --short --branch
   ```

2. Verify the host services and backend ownership:

   ```bash
   systemctl show xibalba-shield.service -p ActiveState -p MainPID
   systemctl show xibalba-shield-ebpf-helper.service -p ActiveState -p MainPID
   systemctl show xibalba-shield-backend.service -p ActiveState -p MainPID
   ss -lntp | grep ':8421' || true
   ```

3. Run the corrected read-only boundary checks:

   ```bash
   ./scripts/verify_backend_service_boundary.sh
   ./scripts/verify_resource_controls.sh
   ```

4. If backend PID ownership is still unmanaged, confirm the exact current PID and command before considering:

   ```bash
   sudo ./scripts/handoff_backend_to_systemd.sh --takeover
   ```

   This remains a deliberate operator action because it can interrupt the local backend. Never infer approval from a healthy HTTP response.

5. Start the UI in an authenticated local development path, then verify:

   - Settings → Hermes Agent renders at desktop and mobile widths.
   - Existing saved settings populate the form.
   - Invalid batch/spool values are rejected by the backend.
   - Saving creates no secret-bearing browser state.
   - Analysis-only and strict-redaction invariants remain non-disableable.
   - Console has no new errors.

6. Only after the authenticated UI journey passes, capture the rendered screenshot and compare it with the concept reference used for the redesign.

## Still blocked or deferred

- Exact gateway/controller model and supported API.
- Disposable lab network scope.
- Production network adapter configuration and acknowledgement.
- Browser-rendered visual proof.
- Explicit backend systemd takeover, if still needed after restart.

No production network mutation, Hermes key rotation, or backend takeover was performed in this pass.
