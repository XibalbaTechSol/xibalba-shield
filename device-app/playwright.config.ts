import { defineConfig, devices } from '@playwright/test'

const port = Number(process.env.SHIELD_DEVICE_PLAYWRIGHT_PORT || 4179)

export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.spec.ts',
  timeout: 30000,
  expect: { timeout: 10000 },
  fullyParallel: true,
  reporter: 'list',
  use: { baseURL: `http://127.0.0.1:${port}` },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `npm run build && npm run preview -- --port ${port}`,
    port,
    reuseExistingServer: true,
  },
})
