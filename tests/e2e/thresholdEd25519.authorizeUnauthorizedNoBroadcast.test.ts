/**
 * Threshold Ed25519 (2-party) — authorize unauthorized should not broadcast.
 *
 * Regression for "signed successfully but never dispatches":
 * when `/threshold-ed25519/authorize` returns 401, the client must surface an error
 * and must not call NEAR RPC `send_tx`.
 */

import { test, expect } from '@playwright/test';
import { DEFAULT_TEST_CONFIG } from '../setup/config';
import { createRelayRouter } from '@server/router/express-adaptor';
import { startExpressRouter } from '../relayer/helpers';
import {
  corsHeadersForRoute,
  createInMemoryJwtSessionAdapter,
  installCreateAccountAndRegisterUserMock,
  installFastNearRpcMock,
  makeAuthServiceForThreshold,
  proxyPostJsonAndMutate,
  setupThresholdE2ePage,
} from './thresholdEd25519.testUtils';

test.describe('threshold-ed25519 authorize unauthorized', () => {
  test.setTimeout(180_000);

  test.beforeEach(async ({ page }) => {
    await setupThresholdE2ePage(page);
  });

  test('401 from /authorize surfaces error and does not broadcast', async ({ page }) => {
    const keysOnChain = new Set<string>();
    const nonceByPublicKey = new Map<string, number>();
    let localNearPublicKey = '';
    let thresholdPublicKeyFromKeygen = '';
    let sendTxCount = 0;
    let forceAuthorizeUnauthorized = false;
    let authorizePostCount = 0;

    const { service, threshold } = makeAuthServiceForThreshold(keysOnChain);
    await service.getRelayerAccount();

    const session = createInMemoryJwtSessionAdapter();
    const frontendOrigin = new URL(DEFAULT_TEST_CONFIG.frontendUrl).origin;
    const router = createRelayRouter(service, { corsOrigins: [frontendOrigin], threshold, session });
    const srv = await startExpressRouter(router);

    try {
      await page.route(`${srv.baseUrl}/threshold-ed25519/keygen`, async (route) => {
        await proxyPostJsonAndMutate(route, (json) => {
          thresholdPublicKeyFromKeygen = String((json as any)?.publicKey || '');
          return json;
        });
      });

      await page.route('**/threshold-ed25519/authorize', async (route) => {
        const req = route.request();
        const method = req.method().toUpperCase();
        if (method === 'OPTIONS') {
          await route.fallback();
          return;
        }
        if (method === 'POST') authorizePostCount += 1;
        if (method !== 'POST' || !forceAuthorizeUnauthorized) {
          await route.fallback();
          return;
        }
        const corsHeaders = corsHeadersForRoute(route);
        await route.fulfill({
          status: 401,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({ ok: false, code: 'unauthorized', message: 'threshold session expired or invalid' }),
        });
      });

      await installCreateAccountAndRegisterUserMock(page, {
        relayerBaseUrl: srv.baseUrl,
        onNewPublicKey: (pk) => {
          localNearPublicKey = pk;
          keysOnChain.add(pk);
          nonceByPublicKey.set(pk, 0);
        },
      });

      await installFastNearRpcMock(page, {
        keysOnChain,
        nonceByPublicKey,
        onSendTx: () => {
          sendTxCount += 1;
          if (thresholdPublicKeyFromKeygen) {
            keysOnChain.add(thresholdPublicKeyFromKeygen);
            nonceByPublicKey.set(thresholdPublicKeyFromKeygen, 0);
            if (localNearPublicKey) {
              nonceByPublicKey.set(localNearPublicKey, (nonceByPublicKey.get(localNearPublicKey) ?? 0) + 1);
            }
          }
        },
        strictAccessKeyLookup: true,
      });

      const setup = await page.evaluate(async ({ relayerUrl }) => {
        try {
          const { TatchiPasskey } = await import('/sdk/esm/core/TatchiPasskey/index.js');
          const suffix =
            (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function')
              ? crypto.randomUUID()
              : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
          const accountId = `e2eunauth${suffix}.w3a-v1.testnet`;

          const pm = new TatchiPasskey({
            nearNetwork: 'testnet',
            nearRpcUrl: 'https://test.rpc.fastnear.com',
            contractId: 'w3a-v1.testnet',
            relayer: { url: relayerUrl },
            iframeWallet: { walletOrigin: '' },
          });

          const confirmConfig = { uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 };

          const reg = await pm.registerPasskeyInternal(accountId, { signerMode: { mode: 'local-signer' } }, confirmConfig as any);
          if (!reg?.success) throw new Error(reg?.error || 'registration failed');

          const enrollment = await pm.enrollThresholdEd25519Key(accountId, { relayerUrl });
          if (!enrollment?.success) throw new Error(enrollment?.error || 'threshold enrollment failed');

          (window as any).__thresholdUnauthorizedPm = pm;
          (window as any).__thresholdUnauthorizedAccountId = accountId;
          (window as any).__thresholdUnauthorizedConfirmConfig = confirmConfig;

          return { ok: true };
        } catch (e: any) {
          return { ok: false, error: e?.message || String(e) };
        }
      }, { relayerUrl: srv.baseUrl });

      expect(setup.ok, setup.ok ? '' : setup.error).toBe(true);

      const baselineSendTxCount = sendTxCount;
      forceAuthorizeUnauthorized = true;

      const result = await page.evaluate(async () => {
        try {
          const pm = (window as any).__thresholdUnauthorizedPm;
          const accountId = String((window as any).__thresholdUnauthorizedAccountId || '');
          const confirmConfig = (window as any).__thresholdUnauthorizedConfirmConfig;
          if (!pm || !accountId) throw new Error('missing test state');

          const { ActionType } = await import('/sdk/esm/core/types/actions.js');

          const out = await pm.executeAction({
            nearAccountId: accountId,
            receiverId: 'w3a-v1.testnet',
            actionArgs: { type: ActionType.Transfer, amount: '1' },
            options: {
              signerMode: { mode: 'threshold-signer', behavior: 'strict' },
              confirmationConfig: confirmConfig,
            },
          });

          const ok = out && typeof out === 'object' && 'success' in out && (out as any).success === false;
          return { ok, error: String((out as any)?.error || '') };
        } catch (e: any) {
          return { ok: true, error: e?.message || String(e) };
        }
      });

      expect(
        result.ok,
        `executeAction unexpectedly succeeded (authorizePostCount=${authorizePostCount}, sendTxCount=${sendTxCount}, baselineSendTxCount=${baselineSendTxCount})`,
      ).toBe(true);
      expect(String(result.error)).toContain('threshold session expired or invalid');
      expect(authorizePostCount).toBeGreaterThan(0);
      expect(sendTxCount).toBe(baselineSendTxCount);
    } finally {
      await srv.close().catch(() => undefined);
    }
  });
});
