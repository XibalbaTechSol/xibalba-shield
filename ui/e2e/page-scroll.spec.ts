import { test, expect, type Page } from '@playwright/test'
import { stubShieldApi } from './shieldFixture'

/* Switching pages used to keep the previous page's scroll offset, so Decisions or
 * Network opened part-way down. A new page starts at its top, as in Cortex.
 *
 * This test can fail: drop the window.scrollTo in Dashboard's openView and the
 * final assertion reads back the offset the previous page was left at. */

async function enterConsole(page: Page) {
  await stubShieldApi(page)
  await page.goto('/')
  await expect(page.locator('main.console')).toBeVisible()
}

/** The rail button for a view, by its visible label. */
function railButton(page: Page, label: string) {
  return page.locator('main.console nav button', { hasText: label }).first()
}

test('a console page opens at its top, not where the last one was left', async ({ page }) => {
  await enterConsole(page)

  await railButton(page, 'Decisions').click()
  await expect(page.locator('h1')).toHaveText('Decisions')

  // Guard against a vacuous pass: a page that cannot scroll proves nothing.
  const scrollable = await page.evaluate(
    () => document.documentElement.scrollHeight - window.innerHeight,
  )
  expect(scrollable, 'Decisions is not tall enough to scroll; the test would pass trivially')
    .toBeGreaterThan(200)

  await page.evaluate(() => window.scrollTo({ top: 300, behavior: 'instant' }))
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(200)

  await railButton(page, 'Network').click()
  await expect(page.locator('h1')).toHaveText('Network')

  await expect.poll(() => page.evaluate(() => window.scrollY),
    { message: 'the new page inherited the previous page scroll offset' }).toBe(0)
})
