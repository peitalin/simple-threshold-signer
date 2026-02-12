import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, SDK_ESM_PATHS, sdkEsmPath } from '../setup';
import { DEFAULT_TEST_CONFIG } from '../setup/config';
import bs58 from 'bs58';
import { ed25519 } from '@noble/curves/ed25519.js';

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

test.describe('Threshold Ed25519 rotation helper', () => {
  test.setTimeout(120_000);

  test.beforeEach(async ({ page }) => {
    // This test runs in a same-origin "blank page" harness so we can:
    // - use WebAuthn virtual authenticator + PRF
    // - intercept network calls deterministically (NEAR RPC + relayer endpoints)
    // - read/write IndexedDB (PasskeyNearKeysDB) inside the test page
    const blankPageUrl = new URL('/__test_blank.html', DEFAULT_TEST_CONFIG.frontendUrl).toString();
    await setupBasicPasskeyTest(page, {
      frontendUrl: blankPageUrl,
      skipPasskeyManagerInit: true,
    });

    // setupBasicPasskeyTest() skips bootstrap global fallbacks when tatchi init is skipped.
    // The WebAuthn mocks expect base64UrlEncode/base64UrlDecode to exist on window.
    await page.evaluate(async (base64Path) => {
      const { base64UrlEncode, base64UrlDecode } = await import(base64Path);
      (window as any).base64UrlEncode = base64UrlEncode;
      (window as any).base64UrlDecode = base64UrlDecode;
    }, SDK_ESM_PATHS.base64);
  });

  test('rotateThresholdEd25519Key performs keygen and updates local threshold metadata', async ({ page }) => {
    // What this test validates (end-to-end in browser, with mocked network):
    //
    // 1) Registration (signerMode=threshold-signer) is Option B:
    //    - the client provides `new_public_key` (local/backup key)
    //    - `/create_account_and_register_user` returns `{ relayerKeyId, publicKey, relayerVerifyingShareB64u }`
    //    - the client adds the threshold key on-chain (signed with the local/backup key)
    //    - the SDK stores `threshold_ed25519_2p_v1` key material locally
    //
    // 2) Rotation (`pm.rotateThresholdEd25519Key`) performs:
    //    - `/threshold-ed25519/keygen` to get a fresh `{ relayerKeyId }` (and the same threshold public key)
    //    - updates local threshold key material to the new `relayerKeyId`
    //    - does not submit on-chain AddKey/DeleteKey when the threshold public key remains unchanged
    const consoleMessages: string[] = [];
    const onConsole = (msg: any) => {
      try { consoleMessages.push(`[${msg.type?.() || 'log'}] ${msg.text?.() || String(msg)}`); } catch {}
    };
    const onPageError = (err: any) => {
      try { consoleMessages.push(`[pageerror] ${String(err?.message || err)}`); } catch {}
    };
    page.on('console', onConsole);
    page.on('pageerror', onPageError);

    const viewAccessKeyCalls: Array<{ publicKey: string; known: boolean }> = [];
    let sendTxCount = 0;
    let localNearPublicKey = '';
    let newPublicKeyFieldPresent = false;
    let thresholdPublicKeyOld = '';
    let thresholdPublicKeyNew = '';
    let keygenResponsePublicKeySent = '';
    let keygenResponseRelayerKeyIdSent = '';
    const relayerKeyIdOld = 'relayer-keyid-mock-old';
    const relayerKeyIdNew = 'relayer-keyid-mock-new';

    const relayerVerifyingShareB64uOld = toB64u(ed25519.Point.BASE.toBytes());
    const relayerVerifyingShareB64uNew = relayerVerifyingShareB64uOld;

    const thresholdKeysOnChain = new Set<string>();
    const accountsOnChain = new Set<string>();

    await page.route('**://test.rpc.fastnear.com/**', async (route) => {
      // Mock NEAR JSON-RPC:
      // - `block` provides height/hash for tx context
      // - `call_function` stubs legacy verifier calls (always { verified: true } for this test)
      // - `view_access_key` provides nonce for tx signing
      // - `view_access_key_list` is used to confirm AddKey/DeleteKey effects
      // - `send_tx` is called when we actually submit signed transactions
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

      const blockHash = bs58.encode(Buffer.alloc(32, 5));
      const blockHeight = 999;

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

      if (rpcMethod === 'query' && params?.request_type === 'view_access_key') {
        const requestedPk = String(params?.public_key || '').trim();
        const isKnown =
          (!!requestedPk && requestedPk === localNearPublicKey)
          || (!!requestedPk && thresholdKeysOnChain.has(requestedPk));
        viewAccessKeyCalls.push({ publicKey: requestedPk, known: isKnown });

        if (!isKnown) {
          await route.fulfill({
            status: 200,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id,
              error: {
                code: -32000,
                message: 'Unknown Access Key',
                data: {
                  message: `Unknown Access Key: ${requestedPk || '<empty>'}`,
                },
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
              block_hash: blockHash,
              block_height: blockHeight,
              nonce: sendTxCount,
              permission: 'FullAccess',
            },
          }),
        });
        return;
      }

      if (rpcMethod === 'query' && params?.request_type === 'view_access_key_list') {
        const keys: any[] = [];
        if (localNearPublicKey) {
          keys.push({ public_key: localNearPublicKey, access_key: { nonce: sendTxCount, permission: 'FullAccess' } });
        }
        for (const pk of thresholdKeysOnChain) {
          keys.push({ public_key: pk, access_key: { nonce: 0, permission: 'FullAccess' } });
        }
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({ jsonrpc: '2.0', id, result: { keys } }),
        });
        return;
      }

      if (rpcMethod === 'send_tx') {
        // Option B registration adds the threshold key on-chain (signed with the local/backup key).
        sendTxCount += 1;
        if (thresholdPublicKeyOld) thresholdKeysOnChain.add(thresholdPublicKeyOld);
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
      // Mock the relayer "registration" endpoint:
      // it returns the server share metadata and the computed group public key.
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
      newPublicKeyFieldPresent = Object.prototype.hasOwnProperty.call(payload, 'new_public_key');
      localNearPublicKey = payload?.new_public_key || '';
      const accountId = String(payload?.new_account_id || '');
      if (accountId) {
        accountsOnChain.add(accountId);
      }
      const clientVerifyingShareB64u = payload?.threshold_ed25519?.client_verifying_share_b64u || '';

      thresholdPublicKeyOld = compute2of2GroupPk({
        clientVerifyingShareB64u,
        relayerVerifyingShareB64u: relayerVerifyingShareB64uOld,
      });

      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          success: true,
          transactionHash: `mock_atomic_tx_${Date.now()}`,
          thresholdEd25519: {
            relayerKeyId: relayerKeyIdOld,
            publicKey: thresholdPublicKeyOld,
            relayerVerifyingShareB64u: relayerVerifyingShareB64uOld,
          },
        }),
      });
    });

    await page.route('**/threshold-ed25519/keygen', async (route) => {
      // Mock the relayer keygen endpoint used during rotation.
      // IMPORTANT: the SDK uses `credentials: 'include'`, so for CORS we must echo Origin
      // and set `Access-Control-Allow-Credentials: true` to satisfy the browser.
      const req = route.request();
      const method = req.method().toUpperCase();
      const origin = req.headers()['origin'] || req.headers()['Origin'] || '';
      const corsHeaders = {
        // This endpoint is called with `credentials: 'include'`, so we must echo the origin.
        'Access-Control-Allow-Origin': origin || '*',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        ...(origin ? { 'Access-Control-Allow-Credentials': 'true' } : {}),
      };
      if (method === 'OPTIONS') {
        await route.fulfill({ status: 204, headers: corsHeaders, body: '' });
        return;
      }

      const payload = JSON.parse(req.postData() || '{}');
      const clientVerifyingShareB64u = String(payload?.clientVerifyingShareB64u || '');

      const computed = compute2of2GroupPk({
        clientVerifyingShareB64u,
        relayerVerifyingShareB64u: relayerVerifyingShareB64uNew,
      });
      thresholdPublicKeyNew = thresholdPublicKeyOld || computed;
      keygenResponsePublicKeySent = thresholdPublicKeyNew;
      keygenResponseRelayerKeyIdSent = relayerKeyIdNew;

      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          ok: true,
          relayerKeyId: relayerKeyIdNew,
          publicKey: thresholdPublicKeyNew,
          relayerVerifyingShareB64u: relayerVerifyingShareB64uNew,
        }),
      });
    });

    const result = await page.evaluate(async ({ paths }) => {
      // Run the SDK flow inside the browser context:
      // - register a passkey-backed account with signerMode=threshold-signer (Option B)
      // - rotate the threshold key and return the helper output for assertions
      try {
        const { TatchiPasskey } = await import(paths.tatchi);
        const { PasskeyNearKeysDBManager } = await import(paths.nearKeysDb);
        const suffix =
          (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function')
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
        const accountId = `e2e${suffix}.w3a-v1.testnet`;
        const profileId = `legacy-near:${accountId.toLowerCase()}`;
        const chainId = accountId.toLowerCase().endsWith('.testnet') ? 'near:testnet' : 'near:mainnet';

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

        const reg = await pm.registerPasskeyInternal(
          accountId,
          { signerMode: { mode: 'threshold-signer' } },
          confirmConfig as any,
        );
        if (!reg?.success) {
          return { ok: false, accountId, error: reg?.error || 'registration failed' };
        }

        // Rotation requires the old threshold key material to already be stored.
        const db = new PasskeyNearKeysDBManager();
        const start = Date.now();
        const maxWaitMs = 10_000;
        while (Date.now() - start < maxWaitMs) {
          const existing = await db
            .getKeyMaterialV2(profileId, 1, chainId, 'threshold_share_v1')
            .catch(() => null);
          if (existing) break;
          await new Promise((r) => setTimeout(r, 50));
        }
        const existing = await db
          .getKeyMaterialV2(profileId, 1, chainId, 'threshold_share_v1')
          .catch(() => null);
        if (!existing) {
          return { ok: false, accountId, error: 'threshold enrollment did not complete in time' };
        }

        const rotated = await pm.rotateThresholdEd25519Key(accountId, { deviceNumber: 1 });
        return { ok: true, accountId, rotated };
      } catch (error: any) {
        return { ok: false, accountId: 'unknown', error: error?.message || String(error) };
      }
    }, { paths: IMPORT_PATHS });

    if (!result.ok) {
      throw new Error([
        `rotation test failed: ${result.error || 'unknown'}`,
        '',
        'console:',
        ...consoleMessages.slice(-120),
      ].join('\n'));
    }

    const rotated = result.rotated as any;
    if (!rotated?.success) {
      throw new Error([
        `rotation returned success=false: ${String(rotated?.error || rotated?.warning || 'unknown error')}`,
        `last view_access_key calls: ${JSON.stringify(viewAccessKeyCalls.slice(-12))}`,
        `thresholdKeysOnChain: ${JSON.stringify(Array.from(thresholdKeysOnChain))}`,
        `keygenResponse: ${JSON.stringify({ publicKey: keygenResponsePublicKeySent, relayerKeyId: keygenResponseRelayerKeyIdSent })}`,
        '',
        'console:',
        ...consoleMessages.slice(-120),
      ].join('\n'));
    }

    // Assertions:
    // - registration adds the threshold key on-chain, rotation does not (public key unchanged)
    // - on-chain "key list" reflects the threshold key created at registration
    // - local DB reflects the new threshold material
    expect(sendTxCount).toBe(1);
    expect(newPublicKeyFieldPresent).toBe(true);
    expect(localNearPublicKey).toMatch(/^ed25519:/);
    expect(thresholdPublicKeyOld).toMatch(/^ed25519:/);
    expect(thresholdPublicKeyNew).toMatch(/^ed25519:/);
    expect(thresholdPublicKeyNew).toBe(thresholdPublicKeyOld);

    expect(rotated?.success).toBe(true);
    expect(rotated?.oldPublicKey).toBe(thresholdPublicKeyOld);
    expect(rotated?.oldRelayerKeyId).toBe(relayerKeyIdOld);
    expect(rotated?.publicKey).toBe(thresholdPublicKeyNew);
    expect(rotated?.relayerKeyId).toBe(relayerKeyIdNew);
    expect(rotated?.deleteOldKeyAttempted).toBe(false);
    expect(rotated?.deleteOldKeySuccess).toBe(true);
    expect(String(rotated?.warning || '')).toContain('same threshold public key');

    expect(Array.from(thresholdKeysOnChain)).toEqual([thresholdPublicKeyOld]);

    const stored = await page.evaluate(async ({ paths, accountId }) => {
      const { PasskeyNearKeysDBManager } = await import(paths.nearKeysDb);
      const db = new PasskeyNearKeysDBManager();
      const profileId = `legacy-near:${String(accountId || '').trim().toLowerCase()}`;
      const chainId = String(accountId || '').trim().toLowerCase().endsWith('.testnet')
        ? 'near:testnet'
        : 'near:mainnet';
      const rec = await db.getKeyMaterialV2(profileId, 1, chainId, 'threshold_share_v1');
      return rec ? { ...rec } : null;
    }, { paths: IMPORT_PATHS, accountId: result.accountId });

    expect(stored?.keyKind).toBe('threshold_share_v1');
    expect(stored?.publicKey).toBe(thresholdPublicKeyNew);
    expect(String(stored?.payload?.relayerKeyId || '')).toBe(relayerKeyIdNew);

    page.off('console', onConsole);
    page.off('pageerror', onPageError);
  });
});
