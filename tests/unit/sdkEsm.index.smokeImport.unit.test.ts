import { test, expect } from '@playwright/test';
import { SDK_ESM_PATHS, setupBasicPasskeyTest } from '../setup';

test.describe('SDK ESM smoke import', () => {
  test('imports /sdk/esm/index.js after bootstrap', async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });

    const res = await page.evaluate(async (indexPath) => {
      try {
        const mod = await import(indexPath);
        return { ok: true as const, keys: Object.keys(mod || {}) };
      } catch (error: any) {
        return { ok: false as const, error: error?.message || String(error) };
      }
    }, SDK_ESM_PATHS.index);

    expect(res.ok).toBe(true);
    expect(Array.isArray(res.keys)).toBe(true);
  });
});

