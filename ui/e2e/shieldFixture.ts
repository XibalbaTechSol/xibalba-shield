import type { Page } from '@playwright/test'

/* The Shield control-plane fixture, extracted from runtime-health.spec.ts so the
 * design-system audit renders the same populated console: event cards, badges,
 * tables, the responder interface and the Hermes form. A thin `{}` stub leaves
 * most of those surfaces unrendered, which would let a conformance sweep pass
 * over surfaces it never actually looked at. */

export async function stubShieldApi(page: Page, theme?: 'command-center' | 'light') {
  // The event stream shows the last 24 hours by default, so decision times must be relative to now. (Fixed 2026-09-08 dates
  // made this test fail from the day after they were written.) The exporter's last_event_at below stays a fixed string: the
  // posture panel prints it verbatim and does not window it.
  const decisionTime = (secondsAgo: number) => new Date(Date.now() - secondsAgo * 1000).toISOString()
  await page.addInitScript(() => {
    sessionStorage.setItem('shield-session', '1')
    sessionStorage.setItem('shield-real-only', 'true')
    sessionStorage.setItem('shield-connection', JSON.stringify({
      baseUrl: window.location.origin,
      tenant: 'tenant-a',
      token: 'test-token',
    }))
  })
  if (theme) await page.addInitScript((t) => sessionStorage.setItem('shield-console-theme', t), theme)

  await page.route('**/api/shield/**', async (route) => {
    const path = new URL(route.request().url()).pathname
    if (path === '/api/shield/settings' && route.request().method() === 'POST') {
      const body = route.request().postDataJSON() as { settings?: { hermesMaxBatch?: number } }
      if ((body.settings?.hermesMaxBatch || 0) > 10) {
        await route.fulfill({ status: 422, contentType: 'application/json', body: JSON.stringify({ error: 'hermesMaxBatch must be between 1 and 10' }) })
        return
      }
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ settings: body.settings || {} }) })
      return
    }
    const responses: Record<string, unknown> = {
      '/api/shield/dashboard-summary': {
        decisions_by_action: {},
        device_count: 1,
        devices: [
          { device_id: 'synthetic', synthetic: 1 },
          { device_id: 'live-device', synthetic: 0 },
        ],
        latest_decisions: [{
          received_at: decisionTime(60),
          decision: {
            device_id: 'live-device',
            decision: { action: 'deny', severity: 'medium', reason: 'Live process decision' },
            event_ref: { class: 'process_activity', event_id: 'evt-live-1' },
          },
        }, {
          received_at: decisionTime(61),
          decision: {
            device_id: 'live-device',
            decision: { action: 'contained', severity: 'medium', reason: 'Contained shadow workload' },
            event_ref: { class: 'process_activity', event_id: 'evt-live-2' },
          },
        }, {
          received_at: decisionTime(62),
          decision: {
            device_id: 'live-device',
            decision: { action: 'escalate', severity: 'high', reason: 'Sensitive write requires review' },
            event_ref: { class: 'process_activity', event_id: 'evt-live-3' },
          },
        }, {
          received_at: decisionTime(63),
          decision: {
            device_id: 'live-device',
            decision: { action: 'allowed', severity: 'low', reason: 'Authenticated execution' },
            event_ref: { class: 'process_activity', event_id: 'evt-live-4' },
          },
        }, {
          received_at: decisionTime(64),
          decision: {
            device_id: 'live-device',
            decision: { action: 'log_only', severity: 'low', reason: 'Routine observation' },
            event_ref: { class: 'process_activity', event_id: 'evt-live-5' },
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
      '/api/shield/cortex-outbox': { outbox: { pending: 0, dead_letter: 0 } },
      '/api/shield/hermes-status': { hermes: { health: 'healthy', healthy: true, transport: 'local-spool', pending: 2, acknowledged_total: 11, dead_letters: 0, agent_id: 'did:integrity:test' } },
      '/api/shield/settings': { settings: { hermesEnabled: true, hermesAnalysisOnly: true, hermesRedactionMode: 'strict', hermesEventScope: 'all', hermesMaxBatch: 10, hermesSpoolMaxBytes: 16777216 } },
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(responses[path] || {}) })
  })
}
