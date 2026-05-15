import { test, expect } from '@playwright/test';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const POLICY_FILE = path.resolve(__dirname, '../../sample-policies/mature_tuned.xml');

test.describe('Conversion flow', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('shows upload view on load', async ({ page }) => {
    await expect(page.getByText('Upload ASM Policy')).toBeVisible();
    await expect(page.getByText('WaffleIron')).toBeVisible();
  });

  test('upload advances to analysis with policy info', async ({ page }) => {
    const fileInput = page.locator('input[type="file"]');
    await fileInput.setInputFiles(POLICY_FILE);

    // Should auto-advance to Analysis step and show policy info
    await expect(page.getByText('mature-tuned')).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText('blocking', { exact: true })).toBeVisible();

    // Summary cards should appear
    await expect(page.getByText('Total Features')).toBeVisible();
    await expect(page.getByText('Directly Translated')).toBeVisible();
  });

  test('analysis shows alarm-only decisions table', async ({ page }) => {
    const fileInput = page.locator('input[type="file"]');
    await fileInput.setInputFiles(POLICY_FILE);

    await expect(page.getByText('Alarm-Only Decisions')).toBeVisible({ timeout: 10_000 });
    // Decisions table should have at least one row
    await expect(page.getByText('Signature').first()).toBeVisible();
  });

  test('analysis shows feature translation status', async ({ page }) => {
    const fileInput = page.locator('input[type="file"]');
    await fileInput.setInputFiles(POLICY_FILE);

    await expect(page.getByText('Translates to XC')).toBeVisible({ timeout: 10_000 });
  });

  test('namespace defaults to "default"', async ({ page }) => {
    const fileInput = page.locator('input[type="file"]');
    await fileInput.setInputFiles(POLICY_FILE);

    const nsInput = page.locator('#namespace');
    await expect(nsInput).toBeVisible({ timeout: 10_000 });
    await expect(nsInput).toHaveValue('default');
  });

  test('translate produces export view with outputs', async ({ page }) => {
    const fileInput = page.locator('input[type="file"]');
    await fileInput.setInputFiles(POLICY_FILE);

    // Wait for analysis to load then click Translate
    const translateBtn = page.getByRole('button', { name: /translate/i });
    await expect(translateBtn).toBeVisible({ timeout: 10_000 });
    await translateBtn.click();

    // Should advance to Export step with output tabs
    await expect(page.getByRole('button', { name: 'App Firewall' })).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText('Download JSON')).toBeVisible();
    await expect(page.getByText('Push to XC Tenant')).toBeVisible();
  });

  test('export view shows gap report', async ({ page }) => {
    const fileInput = page.locator('input[type="file"]');
    await fileInput.setInputFiles(POLICY_FILE);

    const translateBtn = page.getByRole('button', { name: /translate/i });
    await expect(translateBtn).toBeVisible({ timeout: 10_000 });
    await translateBtn.click();

    await expect(page.getByRole('heading', { name: 'Gap Report', exact: true })).toBeVisible({ timeout: 10_000 });
    // Gap report should have a download button
    await expect(page.getByRole('button', { name: /download/i }).first()).toBeVisible();
  });

  test('wizard step navigation works', async ({ page }) => {
    const fileInput = page.locator('input[type="file"]');
    await fileInput.setInputFiles(POLICY_FILE);

    // Advance to Export
    const translateBtn = page.getByRole('button', { name: /translate/i });
    await expect(translateBtn).toBeVisible({ timeout: 10_000 });
    await translateBtn.click();
    await expect(page.getByText('Download JSON')).toBeVisible({ timeout: 10_000 });

    // Click "Analysis" step to go back
    await page.getByRole('button', { name: 'Analysis' }).click();
    await expect(page.getByText('Alarm-Only Decisions')).toBeVisible();

    // Click "Upload" step to go back further
    await page.getByRole('button', { name: 'Upload' }).click();
    await expect(page.getByText('Upload ASM Policy')).toBeVisible();
  });

  test('start over resets to upload', async ({ page }) => {
    const fileInput = page.locator('input[type="file"]');
    await fileInput.setInputFiles(POLICY_FILE);

    await expect(page.getByText('mature-tuned')).toBeVisible({ timeout: 10_000 });

    await page.getByRole('button', { name: 'Start Over' }).click();
    await expect(page.getByText('Upload ASM Policy')).toBeVisible();
  });

  test('push modal opens and closes', async ({ page }) => {
    const fileInput = page.locator('input[type="file"]');
    await fileInput.setInputFiles(POLICY_FILE);

    const translateBtn = page.getByRole('button', { name: /translate/i });
    await expect(translateBtn).toBeVisible({ timeout: 10_000 });
    await translateBtn.click();

    // Open push modal
    await page.getByText('Push to XC Tenant').click();
    await expect(page.getByText('XC Connection')).toBeVisible({ timeout: 5_000 });

    // Close it
    await page.getByRole('button', { name: 'Cancel' }).click();
    await expect(page.getByText('XC Connection')).not.toBeVisible();
  });
});
