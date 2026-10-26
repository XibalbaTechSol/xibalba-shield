import { test, expect } from '@playwright/test'

test('Shield Evidence renders populated Jev DecisionTrace', async ({ page }) => {
  await page.addInitScript(() => {
    sessionStorage.setItem('shield-session', '1')
    sessionStorage.setItem('shield-real-only', 'true')
    sessionStorage.setItem('shield-connection', JSON.stringify({ baseUrl: window.location.origin, tenant: 'tenant-a', token: 'test-token' }))
  })
  await page.route('**/api/shield/**', async route => {
    const path = new URL(route.request().url()).pathname
    const responses: Record<string, unknown> = {
      '/api/shield/dashboard-summary': { device_count: 1, devices: [{ device_id: 'live-device', synthetic: 0 }], latest_decisions: [], exporter_status: [] },
      '/api/shield/devices': { devices: [{ device_id: 'live-device', synthetic: 0, status: 'protected' }] },
      '/api/shield/agents': { agents: [] },
      '/api/shield/enforcement-outcomes': { enforcement_outcomes: [] },
      '/api/shield/exporter-status': { exporter_status: [] },
      '/api/shield/integrations': { integrations: [] },
      '/api/shield/detection-quality': { detection_quality: [] },
      '/api/shield/test-events': { test_events: [] },
      '/api/shield/cortex-outbox': { outbox: {} },
      '/api/shield/hermes-status': { hermes: {} },
      '/api/shield/hermes-deliveries': { deliveries: [] },
      '/api/shield/runtime-resources': { resources: {} },
      '/api/shield/decision-trace': {
        trace_id: 'trace-live-1', root: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', valid: true,
        events: [{ event_id: 'evt-live-1', event_hash: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', envelope: { event_type: 'shield.policy_decision', policy_decision: 'deny' }, advisory: { provider_id: 'jev.fixture.v1', status: 'available', risk_category: 'high', transition_probabilities: { continue: 0.35, escalate: 0.65 }, recommended_escalation: true } }],
        disclaimer: 'Observational correlation only; probabilities do not prove causality or execution.',
      },
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(responses[path] || {}) })
  })
  await page.goto('/')
  await page.getByRole('button', { name: 'Evidence', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'DecisionTrace', exact: true })).toBeVisible()
  await expect(page.getByText('jev.fixture.v1 · available', { exact: true })).toBeVisible()
  await expect(page.getByText('Causal claim: false · enforcement remains policy-owned.')).toBeVisible()
  await page.setViewportSize({ width: 390, height: 844 })
  await expect(page.getByRole('heading', { name: 'DecisionTrace', exact: true })).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(await page.evaluate(() => document.documentElement.clientWidth))
})
