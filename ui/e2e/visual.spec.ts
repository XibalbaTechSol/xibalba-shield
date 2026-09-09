import { test, expect } from '@playwright/test';

test.describe('Visual Regression', () => {
  test('Landing page', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveScreenshot('landing.png', { fullPage: true });
  });

  test('Sign In view', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('button', { name: /open console/i }).first().click();
    await expect(page.locator('main.auth')).toBeVisible();
    await expect(page).toHaveScreenshot('signin.png');
  });

  test('landing diagrams render without mobile page overflow', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/');
    await expect(page.locator('.mermaid-svg svg')).toHaveCount(3);
    await expect(page.getByRole('heading', { name: /proof-gated response lifecycle/i })).toBeVisible();
    const dimensions = await page.evaluate(() => ({
      client: document.documentElement.clientWidth,
      scroll: document.documentElement.scrollWidth,
    }));
    expect(dimensions.scroll).toBe(dimensions.client);
  });
});
