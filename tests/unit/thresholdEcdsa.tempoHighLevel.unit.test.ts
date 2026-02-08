import { expect, test, type Page } from '@playwright/test';
import { corsHeadersForRoute } from '../e2e/thresholdEd25519.testUtils';
import {
  runThresholdEcdsaTempoFlow,
  setupThresholdEcdsaTempoHarness,
} from '../helpers/thresholdEcdsaTempoFlow';

type CounterKey = 'authorize' | 'presignInit' | 'presignStep' | 'signInit' | 'signFinalize';
type Counters = Record<CounterKey, number>;

async function observePostCalls(
  page: Page,
  url: string,
  counters: Counters,
  key: CounterKey,
): Promise<void> {
  await page.route(url, async (route) => {
    if (route.request().method().toUpperCase() === 'POST') {
      counters[key] += 1;
    }
    await route.fallback();
  });
}

test.describe('Threshold ECDSA Tempo high-level API', () => {
  test.setTimeout(180_000);

  test('secp256k1 happy path', async ({ page }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    const counters: Counters = {
      authorize: 0,
      presignInit: 0,
      presignStep: 0,
      signInit: 0,
      signFinalize: 0,
    };

    try {
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/authorize`, counters, 'authorize');
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/presign/init`, counters, 'presignInit');
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/presign/step`, counters, 'presignStep');
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/sign/init`, counters, 'signInit');
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/sign/finalize`, counters, 'signFinalize');

      const result = await runThresholdEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
      });

      expect(result.ok, result.error || JSON.stringify(result)).toBe(true);
      expect(result.keygen?.ok).toBe(true);
      expect(result.session?.ok).toBe(true);
      expect(result.session?.sessionId).toBeTruthy();
      expect(result.signed?.chain).toBe('tempo');
      expect(result.signed?.kind).toBe('tempoTransaction');
      expect(result.signed?.rawTxHex?.startsWith('0x')).toBeTruthy();
      expect(counters.authorize).toBeGreaterThanOrEqual(1);
      expect(counters.presignInit).toBeGreaterThanOrEqual(1);
      expect(counters.signInit).toBeGreaterThanOrEqual(1);
      expect(counters.signFinalize).toBeGreaterThanOrEqual(1);
    } finally {
      await harness.close();
    }
  });

  test('fails when threshold session is missing/expired', async ({ page }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    try {
      const result = await runThresholdEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        connectSession: false,
        omitThresholdSessionFromKeyRef: true,
      });

      expect(result.ok).toBe(false);
      const msg = String(result.error || '');
      expect(msg).toMatch(/No cached threshold-ecdsa session token|threshold session expired/i);
    } finally {
      await harness.close();
    }
  });

  test('handles pool_empty by refilling presign and retrying sign/init', async ({ page }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    const counters: Counters = {
      authorize: 0,
      presignInit: 0,
      presignStep: 0,
      signInit: 0,
      signFinalize: 0,
    };
    let forcedPoolEmpty = false;

    try {
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/authorize`, counters, 'authorize');
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/presign/init`, counters, 'presignInit');
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/presign/step`, counters, 'presignStep');
      await observePostCalls(page, `${harness.baseUrl}/threshold-ecdsa/sign/finalize`, counters, 'signFinalize');

      await page.route(`${harness.baseUrl}/threshold-ecdsa/sign/init`, async (route) => {
        if (route.request().method().toUpperCase() === 'POST') {
          counters.signInit += 1;
          if (!forcedPoolEmpty) {
            forcedPoolEmpty = true;
            await route.fulfill({
              status: 200,
              headers: {
                'Content-Type': 'application/json',
                ...corsHeadersForRoute(route),
              },
              body: JSON.stringify({
                ok: false,
                code: 'pool_empty',
                message: 'forced pool-empty for retry path',
              }),
            });
            return;
          }
        }
        await route.fallback();
      });

      const result = await runThresholdEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
      });

      expect(forcedPoolEmpty).toBe(true);
      expect(counters.signInit).toBeGreaterThanOrEqual(2);
      expect(counters.presignInit).toBeGreaterThanOrEqual(2);
      if (!result.ok) {
        expect(String(result.error || '')).toMatch(/bigR mismatch|mpcSessionId expired or invalid/i);
      } else {
        expect(counters.signFinalize).toBeGreaterThanOrEqual(1);
      }
    } finally {
      await harness.close();
    }
  });

  test('fails when PRF-derived share mismatches keyRef binding', async ({ page }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    try {
      const result = await runThresholdEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        keyRefUserId: `mismatch-${Date.now()}.w3a-v1.testnet`,
      });

      expect(result.ok).toBe(false);
      expect(String(result.error || '')).toContain('Derived client share does not match keyRef.clientVerifyingShareB64u');
    } finally {
      await harness.close();
    }
  });
});
