import { expect, test, type Page } from '@playwright/test';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { recoverTransactionAddress, parseTransaction } from 'viem';
import { publicKeyToAddress } from 'viem/accounts';
import { corsHeadersForRoute } from '../e2e/thresholdEd25519.testUtils';
import {
  runThresholdEcdsaTempoFlow,
  setupThresholdEcdsaTempoHarness,
} from '../helpers/thresholdEcdsaTempoFlow';
import { computeEip1559TxHash } from '@/core/signing/chains/evm/eip1559';
import { bytesToHex } from '@/core/signing/chains/evm/bytes';

type CounterKey = 'authorize' | 'presignInit' | 'presignStep' | 'signInit' | 'signFinalize';
type Counters = Record<CounterKey, number>;

const EIP1559_TEST_TX = {
  chainId: 11155111n,
  nonce: 7n,
  maxPriorityFeePerGas: 1_500_000_000n,
  maxFeePerGas: 3_000_000_000n,
  gasLimit: 21_000n,
  to: `0x${'22'.repeat(20)}` as const,
  value: 12_345n,
  data: '0x' as const,
  accessList: [],
};

function asBigInt(value: bigint | number | undefined, field: string): bigint {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') return BigInt(value);
  throw new Error(`Expected ${field} to be bigint/number`);
}

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

  test('eip1559 raw tx is EVM-parseable and recovers threshold signer', async ({ page }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);

    try {
      const result = await runThresholdEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        signingKind: 'eip1559',
      });

      expect(result.ok, result.error || JSON.stringify(result)).toBe(true);
      expect(result.keygen?.ok).toBe(true);
      expect(result.session?.ok).toBe(true);
      expect(result.signed?.chain).toBe('tempo');
      expect(result.signed?.kind).toBe('eip1559');

      if (!result.signed || result.signed.kind !== 'eip1559') {
        throw new Error('Expected eip1559 signed result');
      }

      const expectedSigningHashHex = bytesToHex(computeEip1559TxHash(EIP1559_TEST_TX));
      expect(result.signed.txHashHex).toBe(expectedSigningHashHex);
      expect(result.signed.rawTxHex.startsWith('0x02')).toBe(true);

      const parsedTx = parseTransaction(result.signed.rawTxHex as `0x${string}`);
      expect(parsedTx.type).toBe('eip1559');
      expect(asBigInt(parsedTx.chainId, 'chainId')).toBe(EIP1559_TEST_TX.chainId);
      expect(asBigInt(parsedTx.nonce, 'nonce')).toBe(EIP1559_TEST_TX.nonce);
      expect(asBigInt(parsedTx.maxPriorityFeePerGas, 'maxPriorityFeePerGas')).toBe(EIP1559_TEST_TX.maxPriorityFeePerGas);
      expect(asBigInt(parsedTx.maxFeePerGas, 'maxFeePerGas')).toBe(EIP1559_TEST_TX.maxFeePerGas);
      expect(asBigInt(parsedTx.gas, 'gas')).toBe(EIP1559_TEST_TX.gasLimit);
      expect((parsedTx.to || '').toLowerCase()).toBe(EIP1559_TEST_TX.to.toLowerCase());
      expect(parsedTx.value).toBe(EIP1559_TEST_TX.value);
      expect((parsedTx.data || '0x').toLowerCase()).toBe(EIP1559_TEST_TX.data);
      expect(parsedTx.accessList || []).toEqual([]);

      const recoveredAddress = await recoverTransactionAddress({
        serializedTransaction: result.signed.rawTxHex as `0x${string}`,
      });
      const groupPublicKeyCompressed = Buffer.from(String(result.keygen?.groupPublicKeyB64u || ''), 'base64url');
      expect(groupPublicKeyCompressed.length).toBe(33);

      const groupPoint = secp256k1.Point.fromBytes(groupPublicKeyCompressed);
      const groupPublicKeyUncompressedHex = `0x${groupPoint.toHex(false)}` as `0x${string}`;
      const expectedSignerAddress = publicKeyToAddress(groupPublicKeyUncompressedHex);
      expect(recoveredAddress.toLowerCase()).toBe(expectedSignerAddress.toLowerCase());
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
