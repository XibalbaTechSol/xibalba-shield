import { test, expect, type Page } from '@playwright/test'

// A7: the Settings browser flow for advisory inference, at desktop and 390px. The control plane is mocked at the HTTP
// boundary (as runtime-health.spec.ts does); the rules under test are the form's own and the shape it POSTs. The backend's
// real validation is covered by tests/test_settings_control.py.

type Saved = Record<string, unknown>

async function openInferenceTab(page: Page, posts: Saved[], backendError?: string) {
  await page.addInitScript(() => {
    sessionStorage.setItem('shield-session', '1')
    sessionStorage.setItem('shield-real-only', 'true')
    sessionStorage.setItem('shield-connection', JSON.stringify({ baseUrl: window.location.origin, tenant: 'tenant-a', token: 'test-token' }))
  })
  let stored: Saved = { hermesEnabled: true, hermesAnalysisOnly: true, hermesRedactionMode: 'strict', hermesEventScope: 'all', hermesMaxBatch: 10, hermesSpoolMaxBytes: 16777216 }
  await page.route('**/api/shield/**', async (route) => {
    const path = new URL(route.request().url()).pathname
    if (path === '/api/shield/settings' && route.request().method() === 'POST') {
      const body = route.request().postDataJSON() as { settings: Saved }
      posts.push(body.settings)
      if (backendError) {
        await route.fulfill({ status: 422, contentType: 'application/json', body: JSON.stringify({ error: backendError }) })
        return
      }
      stored = body.settings
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ settings: stored }) })
      return
    }
    const responses: Record<string, unknown> = {
      '/api/shield/settings': { settings: stored },
      '/api/shield/dashboard-summary': { decisions_by_action: {}, device_count: 0, devices: [], latest_decisions: [] },
      '/api/shield/integrations': { integrations: [] },
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(responses[path] || {}) })
  })
  await page.goto('/')
  await page.getByRole('button', { name: 'Open operator profile settings' }).click()
  await page.getByRole('menuitem', { name: 'Settings', exact: true }).click()
  await page.getByRole('tab', { name: 'Advisory Inference' }).click()
  await expect(page.getByRole('heading', { name: 'Advisory inference' })).toBeVisible()
}

test('advisory inference is shadow-only, refuses bad values locally, and saves a bounded payload', async ({ page }) => {
  const posts: Saved[] = []
  await openInferenceTab(page, posts)

  // Fixed by design, shown as such: there is no control to change either.
  await expect(page.getByText('Shadow only (fixed)')).toBeVisible()
  await expect(page.getByText('Strict (fixed)')).toBeVisible()
  await expect(page.getByLabel('Enable advisory inference')).not.toBeChecked()

  // Bad values are refused before any request is made.
  await page.getByRole('combobox', { name: /^Provider/ }).selectOption('llm')
  await page.getByLabel('Enable advisory inference').check()
  await page.getByLabel('Secret reference').fill('sk-live-raw-key')
  await page.getByLabel('Timeout (ms)').fill('10')
  await page.getByLabel('Temperature').fill('2')
  await page.getByRole('button', { name: 'Save advisory inference' }).click()
  await expect(page.getByText('Use a secret:// reference. Raw keys are never accepted or stored here.')).toBeVisible()
  await expect(page.getByText('Timeout (ms) must be a whole number from 50 to 5000.')).toBeVisible()
  await expect(page.getByText('Temperature must be between 0 and 1.')).toBeVisible()
  await expect(page.getByText('This provider needs an endpoint.')).toBeVisible()
  expect(posts).toHaveLength(0)

  // A plain-http remote endpoint is refused; loopback http is allowed.
  await page.getByLabel(/^Endpoint/).fill('http://models.example.com/v1')
  await page.getByRole('button', { name: 'Save advisory inference' }).click()
  await expect(page.getByText('A non-local endpoint must use HTTPS.')).toBeVisible()
  expect(posts).toHaveLength(0)

  // Fix everything and save.
  await page.getByLabel(/^Endpoint/).fill('https://models.example.com/v1')
  await page.getByLabel('Secret reference').fill('secret://jev-key')
  await page.getByLabel('Timeout (ms)').fill('800')
  await page.getByLabel('Temperature').fill('0.2')
  await page.getByLabel('Event classes').fill('process_activity, file_activity, process_activity')
  await page.getByRole('button', { name: 'Save advisory inference' }).click()
  await expect(page.getByText('Advisory inference settings saved. Policy decisions are unaffected.')).toBeVisible()

  expect(posts).toHaveLength(1)
  expect(posts[0]).toMatchObject({
    inferenceEnabled: true, inferenceProvider: 'llm', inferenceMode: 'shadow', inferenceRedactionMode: 'strict',
    inferenceEndpoint: 'https://models.example.com/v1', inferenceSecretRef: 'secret://jev-key',
    inferenceTimeoutMs: 800, inferenceTemperature: 0.2, inferenceEventClasses: ['process_activity', 'file_activity'],
    hermesMaxBatch: 10, // unrelated saved settings are carried through, not dropped
  })
  expect(JSON.stringify(posts[0])).not.toContain('sk-live-raw-key')
})

test('a backend refusal is shown verbatim', async ({ page }) => {
  const posts: Saved[] = []
  await openInferenceTab(page, posts, 'inferenceMaxTokens must be between 32 and 4096')
  await page.getByRole('button', { name: 'Save advisory inference' }).click() // defaults are valid locally
  await expect(page.getByText('inferenceMaxTokens must be between 32 and 4096')).toBeVisible()
  expect(posts).toHaveLength(1)
})

test('disabling a provider keeps inference off even if the toggle was left on', async ({ page }) => {
  const posts: Saved[] = []
  await openInferenceTab(page, posts)
  await page.getByLabel('Enable advisory inference').check()
  await page.getByRole('combobox', { name: /^Provider/ }).selectOption('disabled')
  await page.getByRole('button', { name: 'Save advisory inference' }).click()
  await expect(page.getByText('Advisory inference settings saved.')).toBeVisible()
  expect(posts[0]).toMatchObject({ inferenceEnabled: false, inferenceProvider: 'disabled' })
})

test('the form fits a 390px phone without sideways scrolling', async ({ page }, testInfo) => {
  await openInferenceTab(page, [])  // reach the tab at desktop width, then shrink (the phone nav is a different control)
  await page.setViewportSize({ width: 390, height: 844 })
  await page.getByRole('combobox', { name: /^Provider/ }).selectOption('llm')
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
  expect(overflow).toBeLessThanOrEqual(0)
  const panel = page.locator('#settings-panel-inference')
  const box = await panel.boundingBox()
  expect(box!.width).toBeLessThanOrEqual(390)
  await page.screenshot({ path: testInfo.outputPath('inference-390.png'), fullPage: true })
})
