import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, SDK_ESM_PATHS, sdkEsmPath } from '../setup';
import { DEFAULT_TEST_CONFIG } from '../setup/config';
import bs58 from 'bs58';
import { ed25519 } from '@noble/curves/ed25519.js';
import { createHash } from 'node:crypto';

const IMPORT_PATHS = {
  nearKeysDb: sdkEsmPath('core/IndexedDBManager/passkeyNearKeysDB.js'),
  tatchi: SDK_ESM_PATHS.tatchiPasskey,
} as const;

function toB64u(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

function compute2of2GroupPk(input: {
  clientVerifyingShareB64u: string;
  relayerVerifyingShareB64u: string;
}): string {
  const clientBytes = new Uint8Array(Buffer.from(input.clientVerifyingShareB64u, 'base64url'));
  const relayerBytes = new Uint8Array(Buffer.from(input.relayerVerifyingShareB64u, 'base64url'));
  const clientPoint = ed25519.Point.fromBytes(clientBytes);
  const relayerPoint = ed25519.Point.fromBytes(relayerBytes);
  const groupPoint = clientPoint.multiply(2n).subtract(relayerPoint);
  return `ed25519:${bs58.encode(groupPoint.toBytes())}`;
}

test.describe('Threshold Ed25519 (registration) — threshold-first account creation', () => {
  test.setTimeout(90_000);

  test.beforeEach(async ({ page }) => {
    // We run the core registration flow in same-origin mode for deterministic tests
    // (avoid depending on the wallet iframe host being available).
    const blankPageUrl = new URL('/__test_blank.html', DEFAULT_TEST_CONFIG.frontendUrl).toString();
    await setupBasicPasskeyTest(page, {
      frontendUrl: blankPageUrl,
      skipPasskeyManagerInit: true,
    });

    // setupBasicPasskeyTest() skips bootstrap "global fallbacks" when tatchi init is skipped.
    // WebAuthn mocks expect base64UrlEncode/base64UrlDecode to be present on window.
    await page.evaluate(async (base64Path) => {
      const { base64UrlEncode, base64UrlDecode } = await import(base64Path);
      (window as any).base64UrlEncode = base64UrlEncode;
      (window as any).base64UrlDecode = base64UrlDecode;
    }, SDK_ESM_PATHS.base64);
  });

  test('registration defaults to threshold-signer and stores threshold material without local on-chain bootstrap', async ({ page }) => {
    let sendTxCount = 0;
    let localNearPublicKey = '';
    let thresholdPublicKey = '';
    let newPublicKeyProvided = false;
    let relayIntentDigest32: number[] | null = null;
    const relayerKeyId = 'relayer-keyid-mock-1';
    const relayerVerifyingShareB64u = toB64u(ed25519.Point.BASE.toBytes());
    let thresholdActivatedOnChain = false;
    const accountsOnChain = new Set<string>();

    await page.route('**://test.rpc.fastnear.com/**', async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();

      const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      };

      if (method === 'OPTIONS') {
        await route.fulfill({ status: 204, headers: corsHeaders, body: '' });
        return;
      }

      if (method !== 'POST') {
        return route.fallback();
      }

      let body: any = {};
      try {
        body = JSON.parse(req.postData() || '{}');
      } catch {
        body = {};
      }

      const rpcMethod = body?.method;
      const params = body?.params || {};
      const id = body?.id ?? '1';

      const blockHash = bs58.encode(Buffer.alloc(32, 7));
      const blockHeight = 123;

      if (rpcMethod === 'block') {
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: { header: { hash: blockHash, height: blockHeight } },
          }),
        });
        return;
      }

      if (rpcMethod === 'query' && params?.request_type === 'call_function') {
        const methodName = params?.method_name;
        const resultBytes = Array.from(Buffer.from(JSON.stringify({ verified: true }), 'utf8'));
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: { result: resultBytes, logs: [`mock call_function ${String(methodName || '')}`] },
          }),
        });
        return;
      }

      if (rpcMethod === 'query' && params?.request_type === 'view_account') {
        const accountId = String(params?.account_id || '');
        if (!accountsOnChain.has(accountId)) {
          await route.fulfill({
            status: 200,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id,
              error: {
                code: -32000,
                message: 'UNKNOWN_ACCOUNT',
                data: 'UNKNOWN_ACCOUNT',
              },
            }),
          });
          return;
        }
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              amount: '0',
              locked: '0',
              code_hash: '11111111111111111111111111111111',
              storage_usage: 0,
              storage_paid_at: 0,
              block_height: blockHeight,
              block_hash: blockHash,
            },
          }),
        });
        return;
      }

      if (rpcMethod === 'query' && params?.request_type === 'view_account') {
        const accountId = String(params?.account_id || '');
        if (!accountsOnChain.has(accountId)) {
          await route.fulfill({
            status: 200,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id,
              error: {
                code: -32000,
                message: 'UNKNOWN_ACCOUNT',
                data: 'UNKNOWN_ACCOUNT',
              },
            }),
          });
          return;
        }
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              amount: '0',
              locked: '0',
              code_hash: '11111111111111111111111111111111',
              storage_usage: 0,
              storage_paid_at: 0,
              block_height: blockHeight,
              block_hash: blockHash,
            },
          }),
        });
        return;
      }

      if (rpcMethod === 'query' && params?.request_type === 'view_access_key') {
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              block_hash: blockHash,
              block_height: blockHeight,
              nonce: 0,
              permission: 'FullAccess',
            },
          }),
        });
        return;
      }

      if (rpcMethod === 'query' && params?.request_type === 'view_access_key_list') {
        const keys: any[] = [];
        if (localNearPublicKey) {
          keys.push({ public_key: localNearPublicKey, access_key: { nonce: 0, permission: 'FullAccess' } });
        }
        if (thresholdActivatedOnChain && thresholdPublicKey) {
          keys.push({ public_key: thresholdPublicKey, access_key: { nonce: 0, permission: 'FullAccess' } });
        }
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: { keys },
          }),
        });
        return;
      }

      if (rpcMethod === 'send_tx') {
        sendTxCount += 1;
        thresholdActivatedOnChain = true;
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              status: { SuccessValue: '' },
              transaction: { hash: `mock-tx-${Date.now()}` },
              transaction_outcome: { id: `mock-tx-outcome-${Date.now()}` },
              receipts_outcome: [],
            },
          }),
        });
        return;
      }

      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({ jsonrpc: '2.0', id, result: {} }),
      });
    });

    await page.route('**/create_account_and_register_user', async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();

      const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      };

      if (method === 'OPTIONS') {
        await route.fulfill({ status: 204, headers: corsHeaders, body: '' });
        return;
      }

      const post = req.postData() || '{}';
      const payload = JSON.parse(post);
      newPublicKeyProvided = Object.prototype.hasOwnProperty.call(payload, 'new_public_key');
      localNearPublicKey = payload?.new_public_key || '';
      const accountId = String(payload?.new_account_id || '');
      if (accountId) {
        accountsOnChain.add(accountId);
      }
      // Extract the 32-byte challenge digest from the WebAuthn clientDataJSON.
      // This should be `sha256("register:<accountId>:<deviceNumber>")` (base64url).
      const clientDataJSONB64u = payload?.webauthn_registration?.response?.clientDataJSON;
      if (typeof clientDataJSONB64u === 'string' && clientDataJSONB64u) {
        try {
          const clientData = JSON.parse(Buffer.from(clientDataJSONB64u, 'base64url').toString('utf8'));
          const challengeB64u = clientData?.challenge;
          if (typeof challengeB64u === 'string' && challengeB64u) {
            relayIntentDigest32 = Array.from(Buffer.from(challengeB64u, 'base64url'));
          }
        } catch {}
      }
      const clientVerifyingShareB64u = payload?.threshold_ed25519?.client_verifying_share_b64u || '';

      thresholdPublicKey = compute2of2GroupPk({
        clientVerifyingShareB64u,
        relayerVerifyingShareB64u,
      });
      // Threshold-only: relay creates the account directly with the threshold key.
      thresholdActivatedOnChain = true;

      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          success: true,
          transactionHash: `mock_atomic_tx_${Date.now()}`,
          thresholdEd25519: {
            relayerKeyId,
            publicKey: thresholdPublicKey,
            relayerVerifyingShareB64u,
          },
        }),
      });
    });

    const registration = await page.evaluate(async ({ paths }) => {
      try {
        const { TatchiPasskey } = await import(paths.tatchi);
        const suffix =
          (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function')
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
        const accountId = `e2e${suffix}.w3a-v1.testnet`;

        const pm = new TatchiPasskey({
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          contractId: 'w3a-v1.testnet',
          relayer: { url: 'http://localhost:3000' },
          iframeWallet: { walletOrigin: '' },
        });

        const confirmConfig = {
          uiMode: 'none',
          behavior: 'skipClick',
          autoProceedDelay: 0,
        };

        (window as any).__registrationEvents = [];

        const res = await pm.registerPasskeyInternal(
          accountId,
          {
            onEvent: (event: any) => {
              try {
                (window as any).__registrationEvents.push(event);
              } catch {}
            },
          },
          confirmConfig as any,
        );

        return { accountId, success: !!res?.success, error: res?.error };
      } catch (error: any) {
        return { accountId: 'unknown', success: false, error: error?.message || String(error) };
      }
    }, { paths: IMPORT_PATHS });

    if (!registration.success) {
      throw new Error(`registration failed: ${registration.error || 'unknown'}`);
    }

    expect(sendTxCount).toBe(0);
    expect(newPublicKeyProvided).toBe(false);
    expect(localNearPublicKey).toBe('');
    expect(thresholdActivatedOnChain).toBe(true);
    expect(thresholdPublicKey).toMatch(/^ed25519:/);
    expect(relayIntentDigest32).toBeTruthy();
    expect(relayIntentDigest32).toHaveLength(32);
    // ConfirmTxFlow binds `sha256("register:<accountId>:<deviceNumber>")` into the WebAuthn challenge.
    const expectedIntentDigest32 = Array.from(
      createHash('sha256')
        .update(`register:${registration.accountId}:1`, 'utf8')
        .digest(),
    );
    expect(relayIntentDigest32).toEqual(expectedIntentDigest32);

    // Wait for local vault to be updated with threshold material.
    await expect
      .poll(async () => {
        return await page.evaluate(async ({ paths, accountId }) => {
          const { PasskeyNearKeysDBManager } = await import(paths.nearKeysDb);
          const db = new PasskeyNearKeysDBManager();
          const profileId = `legacy-near:${String(accountId || '').trim().toLowerCase()}`;
          const chainId = String(accountId || '').trim().toLowerCase().endsWith('.testnet')
            ? 'near:testnet'
            : 'near:mainnet';
          const rec = await db.getKeyMaterialV2(profileId, 1, chainId, 'threshold_share_v1');
          return !!rec;
        }, { paths: IMPORT_PATHS, accountId: registration.accountId });
      }, { timeout: 10_000 })
      .toBe(true);

    await expect
      .poll(async () => {
        return await page.evaluate(() => {
          const events = (window as any).__registrationEvents;
          if (!Array.isArray(events)) return null;
          return (
            events.find((e: any) => e?.phase === 'threshold-key-enrollment' && e?.thresholdKeyReady === true) ??
            null
          );
        });
      }, { timeout: 10_000 })
      .not.toBeNull();

    const thresholdReadyEvent = await page.evaluate(() => {
      const events = (window as any).__registrationEvents;
      if (!Array.isArray(events)) return null;
      return (
        events.find((e: any) => e?.phase === 'threshold-key-enrollment' && e?.thresholdKeyReady === true) ?? null
      );
    });

    expect(thresholdReadyEvent?.thresholdPublicKey).toBe(thresholdPublicKey);
    expect(thresholdReadyEvent?.relayerKeyId).toBe(relayerKeyId);

    const stored = await page.evaluate(async ({ paths, accountId }) => {
      const { PasskeyNearKeysDBManager } = await import(paths.nearKeysDb);
      const db = new PasskeyNearKeysDBManager();
      const profileId = `legacy-near:${String(accountId || '').trim().toLowerCase()}`;
      const chainId = String(accountId || '').trim().toLowerCase().endsWith('.testnet')
        ? 'near:testnet'
        : 'near:mainnet';
      const thresholdRec = await db.getKeyMaterialV2(profileId, 1, chainId, 'threshold_share_v1');
      const localRec = await db.getKeyMaterialV2(profileId, 1, chainId, 'local_sk_encrypted_v1');
      return {
        threshold: thresholdRec ? { ...thresholdRec } : null,
        local: localRec ? { ...localRec } : null,
      };
    }, { paths: IMPORT_PATHS, accountId: registration.accountId });

    expect(stored?.threshold?.keyKind).toBe('threshold_share_v1');
    expect(stored?.threshold?.publicKey).toBe(thresholdPublicKey);
    expect(String(stored?.threshold?.payload?.relayerKeyId || '')).toBe(relayerKeyId);
    expect(stored?.local?.keyKind).toBe('local_sk_encrypted_v1');
    expect(String(stored?.local?.payload?.usage || '')).toBe('export-only');
  });

  test('registration fails if relay omits threshold key material (no stored threshold material)', async ({ page }) => {
    let sendTxCount = 0;
    let localNearPublicKey = '';
    let newPublicKeyProvided = false;
    const accountsOnChain = new Set<string>();

    await page.route('**://test.rpc.fastnear.com/**', async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      };

      if (method === 'OPTIONS') {
        await route.fulfill({ status: 204, headers: corsHeaders, body: '' });
        return;
      }
      if (method !== 'POST') return route.fallback();

      let body: any = {};
      try {
        body = JSON.parse(req.postData() || '{}');
      } catch {
        body = {};
      }

      const rpcMethod = body?.method;
      const params = body?.params || {};
      const id = body?.id ?? '1';
      const blockHash = bs58.encode(Buffer.alloc(32, 9));
      const blockHeight = 456;

      if (rpcMethod === 'block') {
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({ jsonrpc: '2.0', id, result: { header: { hash: blockHash, height: blockHeight } } }),
        });
        return;
      }

      if (rpcMethod === 'query' && params?.request_type === 'call_function') {
        const resultBytes = Array.from(Buffer.from(JSON.stringify({ verified: true }), 'utf8'));
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({ jsonrpc: '2.0', id, result: { result: resultBytes, logs: [] } }),
        });
        return;
      }

      if (rpcMethod === 'query' && params?.request_type === 'view_account') {
        const accountId = String(params?.account_id || '');
        if (!accountsOnChain.has(accountId)) {
          await route.fulfill({
            status: 200,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id,
              error: {
                code: -32000,
                message: 'UNKNOWN_ACCOUNT',
                data: 'UNKNOWN_ACCOUNT',
              },
            }),
          });
          return;
        }
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              amount: '0',
              locked: '0',
              code_hash: '11111111111111111111111111111111',
              storage_usage: 0,
              storage_paid_at: 0,
              block_height: blockHeight,
              block_hash: blockHash,
            },
          }),
        });
        return;
      }

      if (rpcMethod === 'query' && params?.request_type === 'view_account') {
        const accountId = String(params?.account_id || '');
        if (!accountsOnChain.has(accountId)) {
          await route.fulfill({
            status: 200,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id,
              error: {
                code: -32000,
                message: 'UNKNOWN_ACCOUNT',
                data: 'UNKNOWN_ACCOUNT',
              },
            }),
          });
          return;
        }
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              amount: '0',
              locked: '0',
              code_hash: '11111111111111111111111111111111',
              storage_usage: 0,
              storage_paid_at: 0,
              block_height: blockHeight,
              block_hash: blockHash,
            },
          }),
        });
        return;
      }

      if (rpcMethod === 'query' && params?.request_type === 'view_access_key') {
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: { block_hash: blockHash, block_height: blockHeight, nonce: 0, permission: 'FullAccess' },
          }),
        });
        return;
      }

      if (rpcMethod === 'query' && params?.request_type === 'view_access_key_list') {
        const keys: any[] = [];
        if (localNearPublicKey) keys.push({ public_key: localNearPublicKey, access_key: { nonce: 0, permission: 'FullAccess' } });
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({ jsonrpc: '2.0', id, result: { keys } }),
        });
        return;
      }

      if (rpcMethod === 'send_tx') {
        sendTxCount += 1;
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              status: { SuccessValue: '' },
              transaction: { hash: `mock-tx-${Date.now()}` },
              transaction_outcome: { id: `mock-tx-outcome-${Date.now()}` },
              receipts_outcome: [],
            },
          }),
        });
        return;
      }

      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({ jsonrpc: '2.0', id, result: {} }),
      });
    });

    await page.route('**/create_account_and_register_user', async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      };
      if (method === 'OPTIONS') {
        await route.fulfill({ status: 204, headers: corsHeaders, body: '' });
        return;
      }

      const payload = JSON.parse(req.postData() || '{}');
      newPublicKeyProvided = Object.prototype.hasOwnProperty.call(payload, 'new_public_key');
      localNearPublicKey = payload?.new_public_key || '';
      const accountId = String(payload?.new_account_id || '');
      if (accountId) {
        accountsOnChain.add(accountId);
      }

      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          success: true,
          transactionHash: `mock_atomic_tx_${Date.now()}`,
          // thresholdEd25519 intentionally omitted
        }),
      });
    });

    const registration = await page.evaluate(async ({ paths }) => {
      try {
        const { TatchiPasskey } = await import(paths.tatchi);
        const suffix =
          (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function')
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
        const accountId = `e2e${suffix}.w3a-v1.testnet`;

        const pm = new TatchiPasskey({
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          contractId: 'w3a-v1.testnet',
          relayer: { url: 'http://localhost:3000' },
          iframeWallet: { walletOrigin: '' },
        });

        const confirmConfig = {
          uiMode: 'none',
          behavior: 'skipClick',
          autoProceedDelay: 0,
        };

        (window as any).__registrationEvents = [];
        const res = await pm.registerPasskeyInternal(
          accountId,
          {
            onEvent: (event: any) => {
              try {
                (window as any).__registrationEvents.push(event);
              } catch {}
            },
          },
          confirmConfig as any,
        );
        return { accountId, success: !!res?.success, error: res?.error };
      } catch (error: any) {
        return { accountId: 'unknown', success: false, error: error?.message || String(error) };
      }
    }, { paths: IMPORT_PATHS });

    expect(registration.success).toBe(false);
    expect(Boolean(registration.error)).toBe(true);
    expect(sendTxCount).toBe(0);
    expect(newPublicKeyProvided).toBe(false);
    expect(localNearPublicKey).toBe('');

    const stored = await page.evaluate(async ({ paths, accountId }) => {
      const { PasskeyNearKeysDBManager } = await import(paths.nearKeysDb);
      const db = new PasskeyNearKeysDBManager();
      const profileId = `legacy-near:${String(accountId || '').trim().toLowerCase()}`;
      const chainId = String(accountId || '').trim().toLowerCase().endsWith('.testnet')
        ? 'near:testnet'
        : 'near:mainnet';
      const rec = await db.getKeyMaterialV2(profileId, 1, chainId, 'threshold_share_v1');
      return rec ? { ...rec } : null;
    }, { paths: IMPORT_PATHS, accountId: registration.accountId });

    expect(stored).toBeNull();
  });
});
