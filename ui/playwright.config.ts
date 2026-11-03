import { defineConfig, devices } from '@playwright/test';

const previewPort = Number(process.env.SHIELD_PLAYWRIGHT_PORT || 4178);

export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.spec.ts',
  timeout: 30000,
  expect: {
    timeout: 15000,
    toHaveScreenshot: { maxDiffPixelRatio: 0.05 },
  },
  fullyParallel: true,
  reporter: 'html',
  use: {
    baseURL: `http://127.0.0.1:${previewPort}`,
    trace: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: `npm run preview -- --host 127.0.0.1 --port ${previewPort}`,
    port: previewPort,
    reuseExistingServer: true,
  },
});
