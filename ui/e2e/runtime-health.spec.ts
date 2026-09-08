import { test, expect } from '@playwright/test'

test('real telemetry overview renders split-runtime health', async ({ page }) => {
  await page.addInitScript(() => {
    sessionStorage.setItem('shield-session', '1')
    sessionStorage.setItem('shield-real-only', 'true')
    sessionStorage.setItem('shield-connection', JSON.stringify({
      baseUrl: window.location.origin,
      tenant: 'tenant-a',
      token: 'test-token',
    }))
  })

  await page.route('**/api/shield/**', async (route) => {
    const path = new URL(route.request().url()).pathname
    const responses: Record<string, unknown> = {
      '/api/shield/dashboard-summary': {
        decisions_by_action: {},
        device_count: 1,
        devices: [
          { device_id: 'synthetic', synthetic: 1 },
          { device_id: 'live-device', synthetic: 0 },
        ],
        latest_decisions: [{
          received_at: '2026-09-08T19:44:16Z',
          decision: {
            device_id: 'live-device',
            decision: { action: 'deny', severity: 'medium', reason: 'Live process decision' },
            event_ref: { class: 'process_activity', event_id: 'evt-live-1' },
          },
        }],
        exporter_status: [],
      },
      '/api/shield/devices': {
        devices: [
          { device_id: 'synthetic', synthetic: 1 },
          { device_id: 'live-device', synthetic: 0, status: 'protected' },
        ],
      },
      '/api/shield/enforcement-outcomes': { enforcement_outcomes: [] },
      '/api/shield/exporter-status': {
        exporter_status: [
          { device_id: 'synthetic', status: { sensors: { attached: false } } },
          { device_id: 'live-device', status: {
            policy: { healthy: true, active_policy_hash: 'sha256:test' },
            opa: { healthy: true },
            sensors: {
              attached: true,
              attach_mode: 'privileged-helper',
              last_event_at: '2026-09-08T19:44:16Z',
              lost_events: 0,
            },
            exporter: { export_failures: 0, spool_pending: 0 },
          } },
        ],
      },
      '/api/shield/integrations': { integrations: [] },
      '/api/shield/detection-quality': { detection_quality: [] },
      '/api/shield/test-events': { test_events: [] },
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(responses[path] || {}) })
  })

  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Runtime health' })).toBeVisible()
  await expect(page.getByText('privileged-helper', { exact: true })).toBeVisible()
  await expect(page.getByText(/events 2026-09-08T19:44:16Z/)).toBeVisible()
  await expect(page.getByText('0 lost events', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Event stream' }).click()
  await expect(page.getByText('Intercepted Events')).toBeVisible()
  await expect(page.getByText('live-device', { exact: true })).toBeVisible()
  await expect(page.getByText('Live process decision', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Shield agent' }).click()
  await expect(page.getByRole('heading', { name: 'Responder interface' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Freeze process' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Kill process' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Unavailable until validated' })).toHaveCount(3)

  await page.getByRole('button', { name: 'Settings', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Settings & Security Posture' })).toBeVisible()
  await page.getByRole('tab', { name: 'Sensors' }).click()
  await expect(page.getByRole('heading', { name: 'Kernel telemetry sources' })).toBeVisible()
  await page.getByRole('tab', { name: 'Control Plane' }).click()
  await expect(page.getByRole('heading', { name: 'TLS and connectivity' })).toBeVisible()

  await page.getByRole('button', { name: 'Policies', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Enforcement controls' })).toBeVisible()
  await page.getByRole('button', { name: 'Enforcement', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Containment', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Evidence' }).click()
  await expect(page.getByRole('heading', { name: 'Export, queue, and verification' })).toBeVisible()
})
