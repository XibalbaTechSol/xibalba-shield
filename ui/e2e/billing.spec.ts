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

  test('renders usage metering panel with period, formula, metrics, and devices table', async ({ page }) => {
    await stubShieldApi(page)
    await page.goto('/')

    const billingBtn = page.locator('aside.side nav button', { hasText: /^Billing$/ }).first()
    await billingBtn.click()

    // Usage metering section
    const usageSection = page.locator('.billing-usage-section')
    await expect(usageSection).toBeVisible()
    await expect(usageSection.getByRole('heading', { name: /Current Period Usage & Allowance/i })).toBeVisible()

    // Period dates & basis
    await expect(usageSection.locator('.period-range')).toContainText('→')
    await expect(usageSection.locator('.status-pill', { hasText: /Calendar Month/i })).toBeVisible()

    // Formula: seats × included_per_device = included
    const formula = usageSection.locator('.period-formula')
    await expect(formula).toContainText('1 seat')
    await expect(formula).toContainText('5,000 / dev')
    await expect(formula).toContainText('5,000 included')

    // Accrued stat & as of
    await expect(usageSection.locator('.accrued-stat .stat-label')).toHaveText('Accrued so far')
    await expect(usageSection.locator('.accrued-stat .stat-val')).toHaveText('$0.00')
    await expect(usageSection.locator('.accrued-stat .stat-sub')).toContainText('Included in plan (Free)')
    await expect(usageSection.locator('.usage-as-of')).toContainText('As of')

    // Metrics grid
    const metricsGrid = usageSection.locator('.usage-metrics-grid')
    await expect(metricsGrid.getByText('BILLABLE DECISIONS')).toBeVisible()
    await expect(metricsGrid.locator('.usage-metric-card').nth(0)).toContainText('1,200')
    await expect(metricsGrid.locator('.usage-metric-card').nth(0)).toContainText('Excludes 45 zone masks, 0 faults')

    await expect(metricsGrid.getByText('REMAINING ALLOWANCE')).toBeVisible()
    await expect(metricsGrid.locator('.usage-metric-card').nth(1)).toContainText('3,800')

    await expect(metricsGrid.getByText('OVERAGE DECISIONS')).toBeVisible()
    await expect(metricsGrid.locator('.usage-metric-card').nth(2)).toContainText('0')

    await expect(metricsGrid.getByText('ACCRUED OVERAGE')).toBeVisible()
    await expect(metricsGrid.locator('.usage-metric-card').nth(3)).toContainText('$0.00')

    // Devices table
    const table = usageSection.locator('.usage-table')
    await expect(table).toBeVisible()
    await expect(table.locator('tbody tr')).toHaveCount(1)
    const row = table.locator('tbody tr').first()
    await expect(row.locator('.device-id-cell code')).toHaveText('device-test-01')
    await expect(row.locator('.billable-col')).toHaveText('1,200')
    await expect(row.locator('td').nth(2)).toHaveText('45')
    await expect(row.locator('td').nth(3)).toHaveText('0')
    await expect(row.locator('td').nth(4)).toHaveText('3')
  })

  test('handles null period by displaying reason and hiding decision numbers', async ({ page }) => {
    await stubShieldApi(page)

    // Override usage with null period and custom reason
    await page.route('**/api/shield/billing/usage*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          tenant_id: 'tenant-a',
          plan_id: 'free',
          status: 'active',
          as_of: '2026-11-14T01:00:00Z',
          period: null,
          reason: 'Billing period not yet known for this subscription.',
          in_trial: false,
          seats: 1,
          included_per_device: 5000,
          included: 0,
          totals: { billable: 0, excluded_mask: 0, excluded_fault: 0 },
          remaining: 0,
          overage_decisions: 0,
          overage_accrued_cents: 0,
          overage_cents_per_1k: null,
          devices: [],
          gaps: [],
        }),
      })
    })

    await page.goto('/')
    const billingBtn = page.locator('aside.side nav button', { hasText: /^Billing$/ }).first()
    await billingBtn.click()

    const usageSection = page.locator('.billing-usage-section')
    await expect(usageSection).toBeVisible()

    // Reason must be displayed
    const nullAlert = usageSection.locator('.usage-null-period')
    await expect(nullAlert).toBeVisible()
    await expect(nullAlert).toContainText('Billing period not yet known for this subscription.')

    // Numbers, counters, formula card, and metrics grid must NOT be rendered
    await expect(usageSection.locator('.usage-period-card')).not.toBeVisible()
    await expect(usageSection.locator('.usage-metrics-grid')).not.toBeVisible()
    await expect(usageSection.locator('.usage-progress-wrap')).not.toBeVisible()
  })

  test('flags receipt ledger gaps and identifies affected devices in table', async ({ page }) => {
    await stubShieldApi(page)

    await page.route('**/api/shield/billing/usage*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          tenant_id: 'tenant-a',
          plan_id: 'pro',
          status: 'active',
          as_of: '2026-11-14T01:00:00Z',
          period: {
            start: '2026-11-01T00:00:00Z',
            end: '2026-12-01T00:00:00Z',
            basis: 'subscription',
          },
          in_trial: false,
          seats: 2,
          included_per_device: 25000,
          included: 50000,
          totals: { billable: 15000, excluded_mask: 120, excluded_fault: 5 },
          remaining: 35000,
          overage_decisions: 0,
          overage_accrued_cents: 0,
          overage_cents_per_1k: 40,
          devices: [
            { device_id: 'dev-gap-01', billable: 5000, excluded_mask: 20, excluded_fault: 5, reports: 1 },
            { device_id: 'dev-clean-02', billable: 10000, excluded_mask: 100, excluded_fault: 0, reports: 2 },
          ],
          gaps: ['dev-gap-01: missing receipt sequence [42..45]'],
        }),
      })
    })

    await page.goto('/')
    const billingBtn = page.locator('aside.side nav button', { hasText: /^Billing$/ }).first()
    await billingBtn.click()

    const usageSection = page.locator('.billing-usage-section')

    // Basis pill should show Subscription
    await expect(usageSection.locator('.status-pill', { hasText: /Subscription/i })).toBeVisible()

    // Gaps alert must be present
    const gapsAlert = usageSection.locator('.usage-gaps-alert')
    await expect(gapsAlert).toBeVisible()
    await expect(gapsAlert).toContainText('Receipt Ledger Gaps Detected (1)')
    await expect(gapsAlert).toContainText('dev-gap-01: missing receipt sequence [42..45]')

    // Device table must flag dev-gap-01 but not dev-clean-02
    const table = usageSection.locator('.usage-table')
    const gapRow = table.locator('tr.row-has-gap')
    await expect(gapRow).toHaveCount(1)
    await expect(gapRow.locator('.device-id-cell code')).toHaveText('dev-gap-01')
    await expect(gapRow.locator('.gap-flag')).toBeVisible()

    const cleanRow = table.locator('tbody tr:not(.row-has-gap)')
    await expect(cleanRow.locator('.device-id-cell code')).toHaveText('dev-clean-02')
    await expect(cleanRow.locator('.gap-flag')).not.toBeVisible()
  })

  test('displays paid plan overage rate and accrued overage when exceeding allowance', async ({ page }) => {
    await stubShieldApi(page)

    await page.route('**/api/shield/billing/usage*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          tenant_id: 'tenant-a',
          plan_id: 'pro',
          status: 'active',
          as_of: '2026-11-14T01:00:00Z',
          period: {
            start: '2026-11-01T00:00:00Z',
            end: '2026-12-01T00:00:00Z',
            basis: 'subscription',
          },
          in_trial: false,
          seats: 1,
          included_per_device: 25000,
          included: 25000,
          totals: { billable: 27500, excluded_mask: 0, excluded_fault: 0 },
          remaining: 0,
          overage_decisions: 2500,
          overage_accrued_cents: 100,
          overage_cents_per_1k: 40,
          devices: [
            { device_id: 'dev-pro-01', billable: 27500, excluded_mask: 0, excluded_fault: 0, reports: 5 },
          ],
          gaps: [],
        }),
      })
    })

    await page.goto('/')
    const billingBtn = page.locator('aside.side nav button', { hasText: /^Billing$/ }).first()
    await billingBtn.click()

    const usageSection = page.locator('.billing-usage-section')

    // Accrued so far is $1.00
    await expect(usageSection.locator('.accrued-stat .stat-val')).toHaveText('$1.00')
    await expect(usageSection.locator('.accrued-stat .stat-sub')).toHaveText('$0.40 / 1,000 decisions')

    // Metrics grid shows remaining 0 and overage 2,500 with accrued $1.00
    const metricsGrid = usageSection.locator('.usage-metrics-grid')
    await expect(metricsGrid.locator('.usage-metric-card').nth(1).locator('.metric-value')).toHaveText('0')
    await expect(metricsGrid.locator('.usage-metric-card').nth(2).locator('.metric-value')).toHaveText('2,500')
    await expect(metricsGrid.locator('.usage-metric-card').nth(2).locator('.metric-value')).toHaveClass(/overage-warn/)
    await expect(metricsGrid.locator('.usage-metric-card').nth(3).locator('.metric-value')).toHaveText('$1.00')
  })
})
