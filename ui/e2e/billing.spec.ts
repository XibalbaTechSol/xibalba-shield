import { test, expect } from '@playwright/test'
import { stubShieldApi } from './shieldFixture'

test.describe('Shield Billing & Stripe Subscription UI', () => {
  test('navigates to Billing view from sidebar and renders catalog', async ({ page }) => {
    await stubShieldApi(page)
    await page.goto('/')
    await expect(page.locator('main.console')).toBeVisible()

    // Click Billing in sidebar
    const billingBtn = page.locator('aside.side nav button', { hasText: /^Billing$/ }).first()
    await expect(billingBtn).toBeVisible()
    await billingBtn.click()

    // Check header
    await expect(page.getByRole('heading', { name: /Shield Subscription & Entitlements/i })).toBeVisible()

    // Check metric cards
    await expect(page.locator('.billing-metrics-panel')).toBeVisible()
    await expect(page.getByText('CURRENT TIER')).toBeVisible()
    await expect(page.getByText('ENROLLED SEATS')).toBeVisible()

    // Check plan cards: Free, Pro, Team
    await expect(page.locator('.billing-plan-card')).toHaveCount(3)
    await expect(page.getByRole('heading', { name: 'Free' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Pro' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Team' })).toBeVisible()

    // Free is current plan
    const freeCard = page.getByRole('article', { name: 'Free Plan' })
    await expect(freeCard.locator('.plan-badge-top')).toHaveText('CURRENT PLAN')
    await expect(freeCard.locator('.plan-btn')).toBeDisabled()

    // Pro is actionable
    const proCard = page.getByRole('article', { name: 'Pro Plan' })
    await expect(proCard.locator('.plan-price .currency')).toHaveText('$12.00')
    await expect(proCard.locator('.plan-btn')).toHaveText(/Start free trial|Upgrade to Pro/i)
  })

  test('initiates checkout on clicking upgrade button', async ({ page }) => {
    await stubShieldApi(page)
    await page.goto('/')

    const billingBtn = page.locator('aside.side nav button', { hasText: /^Billing$/ }).first()
    await billingBtn.click()

    // Intercept checkout navigation
    let checkoutBody: unknown = null
    await page.route('**/api/shield/billing/checkout', async (route) => {
      checkoutBody = route.request().postDataJSON()
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ url: 'https://checkout.stripe.com/c/pay/cs_test_mock123' }),
      })
    })

    const proCard = page.getByRole('article', { name: 'Pro Plan' })
    await proCard.locator('.plan-btn').click()

    // Verify request payload
    expect(checkoutBody).toEqual({ tenant_id: 'tenant-a', plan_id: 'pro' })
  })

  test('synchronizes seats when clicking Sync Seats Now', async ({ page }) => {
    await stubShieldApi(page)
    await page.goto('/')

    const billingBtn = page.locator('aside.side nav button', { hasText: /^Billing$/ }).first()
    await billingBtn.click()

    let syncCalled = false
    await page.route('**/api/shield/billing/sync', async (route) => {
      syncCalled = true
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ synced: true, quantity: 3, changed: true }),
      })
    })

    const syncBtn = page.locator('button', { hasText: /Sync Seats Now/i })
    await syncBtn.click()

    await expect(page.locator('.billing-alert.info')).toContainText('Seats synchronized: 3 device(s) registered')
    expect(syncCalled).toBe(true)
  })

  test('displays checkout return success banner upon return from Stripe', async ({ page }) => {
    await stubShieldApi(page)
    await page.goto('/?checkout=success')

    // Initial load should route to billing and show success banner
    await expect(page.getByRole('heading', { name: /Shield Subscription & Entitlements/i })).toBeVisible()
    await expect(page.locator('.billing-alert.success')).toBeVisible()
    await expect(page.locator('.billing-alert.success')).toContainText('Checkout completed successfully')
  })

  test('displays checkout return canceled banner upon return from Stripe', async ({ page }) => {
    await stubShieldApi(page)
    await page.goto('/?checkout=canceled')

    await expect(page.getByRole('heading', { name: /Shield Subscription & Entitlements/i })).toBeVisible()
    await expect(page.locator('.billing-alert.info')).toBeVisible()
    await expect(page.locator('.billing-alert.info')).toContainText('Checkout canceled')
  })
})
