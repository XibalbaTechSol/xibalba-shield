import { test, expect } from '@playwright/test'

// The OPA view must show what the running daemon reports (via the backend's live
// /api/shield/opa/policies), including packs that are NOT loaded and loaded copies that
// differ from the shipped file. API responses are mocked here; the backend half is
// covered by tests/test_backend.py (fake OPA daemon).
test('OPA policies view shows live load status per pack', async ({ page }) => {
  await page.addInitScript(() => {
    sessionStorage.setItem('shield-session', '1')
    sessionStorage.setItem('shield-real-only', 'true')
    sessionStorage.setItem('shield-connection', JSON.stringify({ baseUrl: window.location.origin, tenant: 'tenant-a', token: 'test-token' }))
  })
  await page.route('**/api/shield/**', async (route) => {
    const path = new URL(route.request().url()).pathname
    const body = path === '/api/shield/opa/policies'
      ? {
          opa_url: 'http://127.0.0.1:8181', reachable: true, daemon_status: 'healthy', opa_version: '1.18.2', loaded_policy_count: 5,
          policies: [
            { id: 'smb', name: 'SMB & Autonomous Workspace', version: 'smb-2026.08', file: 'smb.rego', rego: 'package shield.policy', loaded: true, loaded_id: 'shield/policies/rego/smb.rego', in_sync: true },
            { id: 'professional-services', name: 'Professional Services & Client Data', version: 'professional-services-2026.08', file: 'professional-services.rego', rego: 'package shield.policy', loaded: true, loaded_id: 'professional-services.rego', in_sync: false },
            { id: 'regulated', name: 'Regulated Enterprise & Healthcare', version: 'regulated-2026.08', file: 'regulated.rego', rego: 'package shield.policy', loaded: false, loaded_id: null, in_sync: null },
          ],
        }
      : {}
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
  })

  await page.goto('/')
  // The OPA view lives under Configuration (it used to be a tab under Policies).
  await page.getByRole('button', { name: 'Configuration', exact: true }).click()
  // Two headings match case-insensitively: the Configuration section ("OPA policies") and the view's own ("OPA Policies").
  await expect(page.getByRole('heading', { name: 'OPA policies', exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'OPA Policies', exact: true })).toBeVisible()
  await expect(page.getByText(/OPA 1\.18\.2 · healthy · http:\/\/127\.0\.0\.1:8181 · 5 policies loaded in total/)).toBeVisible()
  await expect(page.getByRole('cell', { name: 'Loaded', exact: true })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'Loaded — differs from file' })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'Not loaded' })).toBeVisible()
  // The view sits below the policy bundle and integrations on Configuration: bring it into the frame for the screenshot.
  await page.getByRole('heading', { name: 'OPA Policies', exact: true }).scrollIntoViewIfNeeded()
  await page.screenshot({ path: process.env.OPA_SHOT || 'test-results/opa-policies.png', fullPage: false })
})
