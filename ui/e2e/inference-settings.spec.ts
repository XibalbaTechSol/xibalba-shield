import { test, expect } from '@playwright/test'

const inferenceSettings = {
  inferenceEnabled: false,
  inferenceProvider: 'disabled',
  inferenceMode: 'shadow',
  inferenceModel: '',
  inferenceEndpoint: '',
  inferencePromptProfile: 'shield-risk-v1',
  inferenceSecretRef: '',
  inferenceTimeoutMs: 750,
  inferenceMaxTokens: 512,
  inferenceTemperature: 0.1,
  inferenceFailureMode: 'continue_with_policy',
  inferenceEventClasses: ['agent_event', 'tool_call', 'process_activity'],
}

test('configures advisory inference from the dedicated Shield settings tab', async ({ page }) => {
  await page.addInitScript(() => {
    sessionStorage.setItem('shield-session', '1')
    sessionStorage.setItem('shield-connection', JSON.stringify({
      baseUrl: window.location.origin,
      tenant: 'tenant-a',
      token: 'test-token',
    }))
  })

  await page.route('**/api/shield/**', async (route) => {
    const path = new URL(route.request().url()).pathname
    if (path === '/api/shield/settings' && route.request().method() === 'POST') {
      const body = route.request().postDataJSON() as { settings?: Record<string, unknown> }
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ settings: body.settings || {} }) })
      return
    }
    if (path === '/api/shield/settings') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ settings: inferenceSettings }) })
      return
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({}) })
  })

  await page.goto('/')
  await page.getByRole('button', { name: 'Open operator profile settings' }).click()
  await page.getByRole('menuitem', { name: 'Settings', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Settings & Security Posture' })).toBeVisible()
  await page.getByRole('tab', { name: 'Inference & Analysis' }).click()
  await expect(page.getByRole('heading', { name: 'Choose the analysis provider' })).toBeVisible()

  await page.getByLabel('Provider', { exact: true }).selectOption('llm')
  await page.getByLabel('Model').fill('local-reviewer-7b')
  await page.getByLabel('Endpoint').fill('http://127.0.0.1:11434/v1/chat/completions')
  await page.getByLabel('Prompt profile').fill('shield-risk-review-v2')
  await page.getByLabel('Enable advisory inference').check()
  await page.getByRole('button', { name: 'Save inference profile' }).click()
  await expect(page.getByText('Inference profile saved.', { exact: false })).toContainText('Enforcement remains deterministic and policy-owned.')

  await page.screenshot({ path: '/tmp/shield-inference-settings-desktop.png', fullPage: true })
  await page.setViewportSize({ width: 390, height: 844 })
  await expect(page.getByRole('heading', { name: 'Choose the analysis provider' })).toBeVisible()
  const mobileWidth = await page.evaluate(() => ({ clientWidth: document.documentElement.clientWidth, scrollWidth: document.documentElement.scrollWidth }))
  expect(mobileWidth.scrollWidth).toBeLessThanOrEqual(mobileWidth.clientWidth + 1)
  await page.screenshot({ path: '/tmp/shield-inference-settings-mobile.png', fullPage: true })
})
