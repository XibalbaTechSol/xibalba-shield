import { test, expect } from '@playwright/test'
import { stubShieldApi } from './shieldFixture'

test('real telemetry overview renders split-runtime health', async ({ page }) => {
  await stubShieldApi(page)

  await page.goto('/')
  // Posture: split-runtime health.
  await expect(page.getByRole('heading', { name: 'Runtime health' })).toBeVisible()
  await expect(page.getByText('privileged-helper', { exact: true })).toBeVisible()
  await expect(page.getByText(/events 2026-09-08T19:44:16Z/)).toBeVisible()
  await expect(page.getByText('0 lost events', { exact: true })).toBeVisible()

  // Decisions > Event stream: durable decisions from the control plane, filterable by action.
  await page.getByRole('button', { name: 'Decisions', exact: true }).click()
  await page.getByRole('tab', { name: 'Event stream' }).click()
  await expect(page.getByText('Intercepted Events')).toBeVisible()
  await expect(page.getByText('live-device', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('Live process decision', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Contained (1)' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Denied (1)' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Escalated (1)' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Allowed (1)' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Logged (1)' })).toBeVisible()

  // Agent: responder interface (actions stay unavailable until validated) and the Hermes profile form.
  await page.getByRole('button', { name: 'Agent', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Responder interface' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Freeze process' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Kill process' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Unavailable until validated' })).toHaveCount(3)
  await expect(page.getByRole('heading', { name: 'Hermes Shield agent' })).toBeVisible()
  await expect(page.getByText('11 acknowledged', { exact: false })).toBeVisible()
  await expect(page.getByText('Analysis only · enforced', { exact: true })).toBeVisible()
  await page.getByLabel('Maximum batch').fill('11')
  await page.getByRole('button', { name: 'Save Hermes profile' }).click()
  await expect(page.getByRole('alert')).toContainText('hermesMaxBatch must be between 1 and 10')
  await page.getByLabel('Maximum batch').fill('10')
  await page.getByRole('button', { name: 'Save Hermes profile' }).click()
  await expect(page.getByText('Saved', { exact: true })).toBeVisible()

  // Settings (operator profile menu): sensors and control-plane tabs.
  await page.getByRole('button', { name: 'Open operator profile settings' }).click()
  await page.getByRole('menuitem', { name: 'Settings', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Settings & Security Posture' })).toBeVisible()
  await page.getByRole('tab', { name: 'Sensors' }).click()
  await expect(page.getByRole('heading', { name: 'Kernel telemetry sources' })).toBeVisible()
  await page.getByRole('tab', { name: 'Control Plane' }).click()
  await expect(page.getByRole('heading', { name: 'TLS and connectivity' })).toBeVisible()

  // Decisions > Policy & enforcement, then Evidence.
  await page.getByRole('button', { name: 'Decisions', exact: true }).click()
  await page.getByRole('tab', { name: /Policy & enforcement/ }).click()
  await expect(page.getByRole('heading', { name: 'Enforcement controls' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Containment', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Evidence', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Export, queue, and verification' })).toBeVisible()

  // The agent view still renders at a phone width.
  await page.getByRole('button', { name: 'Agent', exact: true }).click()
  await page.setViewportSize({ width: 390, height: 844 })
  await expect(page.getByRole('heading', { name: 'Hermes Shield agent' })).toBeVisible()
})
