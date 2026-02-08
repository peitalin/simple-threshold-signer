import { expect, test } from '@playwright/test';
import {
  runThresholdEcdsaTempoFlow,
  setupThresholdEcdsaTempoHarness,
} from '../helpers/thresholdEcdsaTempoFlow';

test.describe('threshold-ecdsa tempo signing', () => {
  test.setTimeout(180_000);

  test('keygen -> connect session -> sign tempoTransaction', async ({ page }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    try {
      const result = await runThresholdEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
      });

      expect(result.ok, result.error || JSON.stringify(result)).toBe(true);
      expect(result.keygen?.ok).toBe(true);
      expect(result.keygen?.relayerKeyId).toBeTruthy();
      expect(result.session?.ok).toBe(true);
      expect(result.session?.sessionId).toBeTruthy();
      expect(result.signed?.chain).toBe('tempo');
      expect(result.signed?.kind).toBe('tempoTransaction');
      expect(result.signed?.senderHashHex?.startsWith('0x')).toBeTruthy();
      expect(result.signed?.rawTxHex?.startsWith('0x')).toBeTruthy();
    } finally {
      await harness.close();
    }
  });
});
