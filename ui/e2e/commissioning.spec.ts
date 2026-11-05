import { test, expect } from '@playwright/test'
import { stubShieldApi } from './shieldFixture'

/* Commissioning ladder. The rule under test is the repo's "no silent mocks" applied to a UI:
 * every figure comes from /api/shield/commissioning-metrics, and an absent figure reads
 * "Not measured" -- never 0, which would look like a fast or perfect result. */

const METRICS = {
  scope: { tenant_id: 'tenant-a', device_id: null },
  window: { outcome_rows_read: 14, max_rows: 5000 },
  containment: { attempts: 11, completed: 10, failed: 1, escalated: 0 },
  handle_to_contain_ms: { n: 10, p50: 5.0, p95: 10.0, p99: 10.0, max: 10.0 },
  false_freeze: { completed_contains: 10, linked_resumes: 2, unlinked_resumes: 1, rate: 0.2 },
  observe: { would_actions_total: 7, by_action: { contain: 4, deny: 2, escalate: 1 } },
  not_instrumented: ['event_to_contain_ms: sensor event timestamps are whole-second'],
}

async function openCommissioning(page) {
  await page.goto('/')
  await expect(page.locator('main.console')).toBeVisible()
  await page.getByRole('button', { name: 'Commissioning', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Commissioning ladder' })).toBeVisible()
}

test('shows the evidence the backend holds, per rung', async ({ page }) => {
  await stubShieldApi(page)
  await page.route('**/api/shield/commissioning-metrics*', (route) =>
    route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(METRICS) }))
  await openCommissioning(page)

  const view = page.locator('.commissioning-view')
  // Rung 1: would-actions and their breakdown.
  await expect(view.getByText('contain 4 · deny 2 · escalate 1')).toBeVisible()
  // Rung 3: latency percentiles, counts, and the false-freeze rate with its numerator/denominator.
  await expect(view.getByText('5.00 ms')).toBeVisible()
  await expect(view.getByText('10.0 ms')).toHaveCount(2)
  await expect(view.getByText('11 attempted · 1 failed')).toBeVisible()
  await expect(view.getByText('20.0%')).toBeVisible()
  await expect(view.getByText('2 reversed of 10 · 1 unlinked resumes')).toBeVisible()
  // What the backend says it cannot measure is shown verbatim.
  await expect(view.getByLabel('Not instrumented').getByText(/event_to_contain_ms/)).toBeVisible()
  // Rung 4 names its planned parts rather than implying they ship.
  await expect(view.getByText('[PLANNED]')).toHaveCount(2)
})

test('an empty backend reads Not measured, never zero', async ({ page }) => {
  await stubShieldApi(page) // unknown paths return {}, which is what an uninstrumented backend gives
  await openCommissioning(page)

  const view = page.locator('.commissioning-view')
  await expect(view.getByText('Not measured').first()).toBeVisible()
  const text = await view.innerText()
  // No fabricated zero latency or zero rate anywhere on the ladder.
  expect(text).not.toMatch(/(^|\s)0(\.0+)? ?ms/)
  expect(text).not.toMatch(/(^|\s)0(\.0+)?%/)
})

test('a failing endpoint is reported and nothing is shown as measured', async ({ page }) => {
  await stubShieldApi(page)
  await page.route('**/api/shield/commissioning-metrics*', (route) =>
    route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: 'store unavailable' }) }))
  await openCommissioning(page)

  await expect(page.getByRole('alert')).toContainText('Commissioning metrics unavailable: store unavailable')
  await expect(page.locator('.commissioning-view').getByText('Not measured').first()).toBeVisible()
})

test('selecting a device scopes the request to that device', async ({ page }) => {
  await stubShieldApi(page)
  const urls: string[] = []
  await page.route('**/api/shield/commissioning-metrics*', (route) => {
    urls.push(route.request().url())
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(METRICS) })
  })
  await openCommissioning(page)
  const select = page.getByLabel('Scope')
  const options = await select.locator('option').allTextContents()
  test.skip(options.length < 2, 'fixture exposes no device list to scope by')
  await select.selectOption(options[1])
  await expect.poll(() => urls.some((u) => u.includes('device_id='))).toBe(true)
})
