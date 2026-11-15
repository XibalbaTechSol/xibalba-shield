import { test, expect, type Page } from '@playwright/test'

/* A refused dashboard poll must never revoke the shared session cookie.
 *
 * Why this suite exists: on Render (2026-11-15) a tab still showing tenant-a kept polling after
 * the operator signed in to a new tenant in the same browser. The cookie now belonged to the new
 * tenant, so tenant-a's polls got 401 "invalid admin token"; the dashboard answered by calling
 * POST /api/shield/auth/logout, which revoked the cookie and ended the new tenant's live session.
 * A transient 401 (a backend race, fixed separately) did the same to a single tab. */

type MeReply = { status: number; tenant?: string }

async function stubRefusingPolls(page: Page, me: MeReply): Promise<{ logouts: number }> {
  const seen = { logouts: 0 }
  await page.addInitScript(() => {
    sessionStorage.setItem('shield-session', '1')
    sessionStorage.setItem('shield-real-only', 'true')
    // A cookie session (no machine token), the way a signed-in operator's tab holds it.
    sessionStorage.setItem('shield-connection', JSON.stringify({ baseUrl: window.location.origin, tenant: 'tenant-a', token: '' }))
  })
  await page.route('**/api/shield/**', async (route) => {
    const path = new URL(route.request().url()).pathname
    if (path === '/api/shield/auth/logout') {
      seen.logouts += 1
      await route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' })
      return
    }
    if (path === '/api/shield/auth/me') {
      const body = me.tenant
        ? { account: { id: 'acct', email: 'op@example.com', tenant_id: me.tenant }, tenant_id: me.tenant, session_expires_at: '2099-01-01T00:00:00Z' }
        : { error: 'authentication required: session cookie or admin token' }
      await route.fulfill({ status: me.status, contentType: 'application/json', body: JSON.stringify(body) })
      return
    }
    await route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ error: 'invalid admin token' }) })
  })
  await page.route('**/cortex/**', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }))
  return seen
}

test.describe('Dashboard 401 handling', () => {
  test('cookie now belongs to another tenant: sign this tab out locally, never revoke', async ({ page }) => {
    const seen = await stubRefusingPolls(page, { status: 200, tenant: 'team-e2e' })
    await page.goto('/')
    await expect(page.getByText(/signed in to team-e2e in another tab/i)).toBeVisible()
    expect(seen.logouts).toBe(0)
  })

  test('session still valid for this tenant: a refused poll is transient, stay on the console', async ({ page }) => {
    const seen = await stubRefusingPolls(page, { status: 200, tenant: 'tenant-a' })
    await page.goto('/')
    await expect(page.locator('main.console')).toBeVisible()
    await page.waitForTimeout(6000) // span a second poll
    await expect(page.locator('main.console')).toBeVisible()
    expect(seen.logouts).toBe(0)
  })

  test('session really gone: sign in again, without a revoke call', async ({ page }) => {
    const seen = await stubRefusingPolls(page, { status: 401 })
    await page.goto('/')
    await expect(page.getByText(/Session expired\. Sign in again/i)).toBeVisible()
    expect(seen.logouts).toBe(0)
  })

  test('the Log out button still revokes the session on the server', async ({ page }) => {
    const seen = await stubRefusingPolls(page, { status: 200, tenant: 'tenant-a' })
    await page.goto('/')
    await expect(page.locator('main.console')).toBeVisible()
    await page.evaluate(() => {
      const button = [...document.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Log out') as HTMLButtonElement | undefined
      button?.click()
    })
    await expect.poll(() => seen.logouts).toBe(1)
  })
})
