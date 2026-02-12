import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest, handleInfrastructureErrors } from '../setup';

const IMPORT_PATHS = {
  linkDevice: '/sdk/esm/core/TatchiPasskey/linkDevice.js',
  clientDb: '/sdk/esm/core/IndexedDBManager/passkeyClientDB.js',
  nearKeysDb: '/sdk/esm/core/IndexedDBManager/passkeyNearKeysDB.js',
  getDeviceNumber: '/sdk/esm/core/signing/webauthn/device/getDeviceNumber.js',
  signTxs: '/sdk/esm/core/signing/chainAdaptors/near/handlers/signTransactionsWithActions.js',
  signerTypes: '/sdk/esm/core/types/signer-worker.js',
  actions: '/sdk/esm/core/types/actions.js',
} as const;

test.describe('Link device → immediate sign (regression)', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('linkDevice storage leaves account immediately signable', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      try {
        const { LinkDeviceFlow } = await import(paths.linkDevice);
        const { PasskeyClientDBManager } = await import(paths.clientDb);
        const { PasskeyNearKeysDBManager } = await import(paths.nearKeysDb);
        const { getLastLoggedInDeviceNumber } = await import(paths.getDeviceNumber);
        const { signTransactionsWithActions } = await import(paths.signTxs);
        const { WorkerResponseType } = await import(paths.signerTypes);
        const { ActionType } = await import(paths.actions);

        const nearAccountId = 'linkdev1.w3a-v1.testnet';
        const deviceNumber = 2;
        const profileId = `legacy-near:${nearAccountId.toLowerCase()}`;
        const chainId = nearAccountId.toLowerCase().endsWith('.testnet') ? 'near:testnet' : 'near:mainnet';

        // Use a per-test DB instance (the global IndexedDBManager is disabled on the app origin in wallet-iframe mode).
        const suffix =
          (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function')
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
        const clientDB = new PasskeyClientDBManager();
        clientDB.setDbName(`PasskeyClientDB-linkDeviceImmediateSign-${suffix}`);
        const nearKeysDB = new PasskeyNearKeysDBManager();
        nearKeysDB.setDbName(`PasskeyNearKeys-linkDeviceImmediateSign-${suffix}`);

        // Provide a minimal WebAuthnManager facade for the private storage helper.
        // This keeps the regression deterministic and avoids relying on app-origin persistence.
        const webAuthnManager: any = {
          storeUserData: async (userData: any) => {
            await clientDB.upsertNearAccountProjection(userData);
          },
          storeAuthenticator: async (authenticatorData: any) => {
            await clientDB.upsertNearAuthenticator({
              ...authenticatorData,
              deviceNumber: authenticatorData.deviceNumber ?? 1,
            });
          },
          extractCosePublicKey: async () => new Uint8Array([1, 2, 3]),
        };

        const ctx: any = {
          webAuthnManager,
          nearClient: null,
          configs: {},
        };

        const dummyCredential = {
          id: 'cred-id',
          rawId: 'cred-rawid-b64u',
          type: 'public-key',
          authenticatorAttachment: 'platform',
          response: {
            clientDataJSON: 'clientDataJSON-b64u',
            attestationObject: 'attestationObject-b64u',
            transports: ['internal'],
          },
          clientExtensionResults: { prf: { results: { first: 'BQ', second: undefined } } },
        };

        const flow = new LinkDeviceFlow(ctx, {});
        // LinkDeviceFlow.storeDeviceAuthenticator is private in TS but callable at runtime.
        (flow as any).session = {
          accountId: nearAccountId,
          deviceNumber,
          nearPublicKey: 'ed25519:temp',
          credential: dummyCredential,
          phase: 'idle',
          createdAt: Date.now(),
          expiresAt: Date.now() + 60_000,
        };

        const deterministicKeysResult = {
          nearPublicKey: 'ed25519:pk-device2',
          credential: dummyCredential,
        };

        await (flow as any).storeDeviceAuthenticator(deterministicKeysResult);

        // LinkDeviceFlow derives/stores the encrypted NEAR key earlier in the real flow.
        // For this regression, store a minimal entry so signing can proceed immediately.
        await nearKeysDB.storeKeyMaterialV2({
          profileId,
          deviceNumber,
          chainId,
          keyKind: 'local_sk_encrypted_v1',
          algorithm: 'ed25519',
          publicKey: 'ed25519:pk-device2',
          wrapKeySalt: 'wrapKeySalt-b64u',
          payload: {
            encryptedSk: 'ciphertext-b64u',
            chacha20NonceB64u: 'nonce-b64u',
          },
          timestamp: Date.now(),
          schemaVersion: 1,
        });

        const last = await clientDB.getLastSelectedNearAccountProjection();
        const deviceFromHelper = await getLastLoggedInDeviceNumber(nearAccountId, clientDB);
        const key = await nearKeysDB.getKeyMaterialV2(profileId, deviceFromHelper, chainId, 'local_sk_encrypted_v1');
        const authenticators = await clientDB.listNearAuthenticators(nearAccountId);

        // Exercise the signing handler path up to and including the IndexedDB lookups.
        // We stub the SecureConfirm confirmation and worker response so the test stays deterministic
        // and focuses on "link device → immediate sign" state wiring.
        const signingCtx: any = {
          indexedDB: {
            clientDB,
            nearKeysDB,
            getNearLocalKeyMaterialV2First: async (accountId: string, deviceNum: number) => {
              const normalizedAccountId = String(accountId || '').trim().toLowerCase();
              const localProfileId = `legacy-near:${normalizedAccountId}`;
              const localChainId = normalizedAccountId.endsWith('.testnet') ? 'near:testnet' : 'near:mainnet';
              const row = await nearKeysDB.getKeyMaterialV2(
                localProfileId,
                deviceNum,
                localChainId,
                'local_sk_encrypted_v1',
              );
              if (!row) return null;
              const wrapKeySalt = String(row.wrapKeySalt || '').trim();
              const encryptedSk = String((row.payload as any)?.encryptedSk || '').trim();
              const chacha20NonceB64u = String((row.payload as any)?.chacha20NonceB64u || '').trim();
              if (!wrapKeySalt || !encryptedSk || !chacha20NonceB64u) return null;
              return {
                nearAccountId: accountId,
                deviceNumber: deviceNum,
                kind: 'local_near_sk_v3' as const,
                publicKey: row.publicKey,
                wrapKeySalt,
                encryptedSk,
                chacha20NonceB64u,
                timestamp: row.timestamp,
              };
            },
            getNearThresholdKeyMaterialV2First: async () => null,
          },
          nonceManager: { initializeUser: () => {} },
          touchIdPrompt: { getRpId: () => 'example.localhost' },
          relayerUrl: 'https://relay-server.localhost',
          postWrapKeySeedToSigner: () => {},
          secureConfirmWorkerManager: {
            confirmAndPrepareSigningSession: async () => ({
              intentDigest: 'intent',
              transactionContext: {
                nearPublicKeyStr: 'ed25519:pk-device2',
                nextNonce: '1',
                txBlockHeight: '1',
                txBlockHash: 'blockhash',
                accessKeyInfo: { nonce: 0 },
              },
              credential: dummyCredential,
            }),
          },
          requestWorkerOperation: async () => ({
            type: WorkerResponseType.SignTransactionsWithActionsSuccess,
            payload: {
              success: true,
              signedTransactions: [
                { transaction: {}, signature: {}, borshBytes: new Uint8Array([1]) },
              ],
              logs: [],
            },
          }),
          sendMessage: async () => ({
            type: WorkerResponseType.SignTransactionsWithActionsSuccess,
            payload: {
              success: true,
              signedTransactions: [
                { transaction: {}, signature: {}, borshBytes: new Uint8Array([1]) },
              ],
              logs: [],
            },
          }),
        };

        const signed = await signTransactionsWithActions({
          ctx: signingCtx,
          transactions: [
            {
              receiverId: nearAccountId,
              actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
            },
          ],
          rpcCall: { nearAccountId },
          signerMode: { mode: 'local-signer' },
          sessionId: 'linkdevice-regression',
        });

        return {
          success: true,
          lastUser: last ? { nearAccountId: last.nearAccountId, deviceNumber: last.deviceNumber } : null,
          deviceFromHelper,
          hasEncryptedKey: key?.keyKind === 'local_sk_encrypted_v1' && !!(key?.payload as any)?.encryptedSk,
          authenticatorCount: Array.isArray(authenticators) ? authenticators.length : 0,
          signedCount: Array.isArray(signed) ? signed.length : 0,
        } as const;
      } catch (error: any) {
        return { success: false, error: error?.message || String(error) } as const;
      }
    }, { paths: IMPORT_PATHS });

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success, result.error || 'unknown error').toBe(true);
      return;
    }

    expect(result.lastUser?.nearAccountId).toBe('linkdev1.w3a-v1.testnet');
    expect(result.lastUser?.deviceNumber).toBe(2);
    expect(result.deviceFromHelper).toBe(2);
    expect(result.hasEncryptedKey).toBe(true);
    expect(result.authenticatorCount).toBeGreaterThan(0);
    expect(result.signedCount).toBe(1);
  });

  test('linkDevice storage coerces string deviceNumber', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      try {
        const { LinkDeviceFlow } = await import(paths.linkDevice);
        const { PasskeyClientDBManager } = await import(paths.clientDb);
        const { PasskeyNearKeysDBManager } = await import(paths.nearKeysDb);
        const { getLastLoggedInDeviceNumber } = await import(paths.getDeviceNumber);
        const { signTransactionsWithActions } = await import(paths.signTxs);
        const { WorkerResponseType } = await import(paths.signerTypes);
        const { ActionType } = await import(paths.actions);

        const nearAccountId = 'linkdev2.w3a-v1.testnet';
        const deviceNumber: any = '2';
        const profileId = `legacy-near:${nearAccountId.toLowerCase()}`;
        const chainId = nearAccountId.toLowerCase().endsWith('.testnet') ? 'near:testnet' : 'near:mainnet';

        // Use a per-test DB instance (the global IndexedDBManager is disabled on the app origin in wallet-iframe mode).
        const suffix =
          (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function')
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
        const clientDB = new PasskeyClientDBManager();
        clientDB.setDbName(`PasskeyClientDB-linkDeviceImmediateSign-${suffix}`);
        const nearKeysDB = new PasskeyNearKeysDBManager();
        nearKeysDB.setDbName(`PasskeyNearKeys-linkDeviceImmediateSign-${suffix}`);

        // Provide a minimal WebAuthnManager facade for the private storage helper.
        const webAuthnManager: any = {
          storeUserData: async (userData: any) => {
            await clientDB.upsertNearAccountProjection(userData);
          },
          storeAuthenticator: async (authenticatorData: any) => {
            await clientDB.upsertNearAuthenticator({
              ...authenticatorData,
              deviceNumber: authenticatorData.deviceNumber ?? 1,
            });
          },
          extractCosePublicKey: async () => new Uint8Array([1, 2, 3]),
        };

        const ctx: any = {
          webAuthnManager,
          nearClient: null,
          configs: {},
        };

        const dummyCredential = {
          id: 'cred-id',
          rawId: 'cred-rawid-b64u',
          type: 'public-key',
          authenticatorAttachment: 'platform',
          response: {
            clientDataJSON: 'clientDataJSON-b64u',
            attestationObject: 'attestationObject-b64u',
            transports: ['internal'],
          },
          clientExtensionResults: { prf: { results: { first: 'BQ', second: undefined } } },
        };

        const flow = new LinkDeviceFlow(ctx, {});
        // LinkDeviceFlow.storeDeviceAuthenticator is private in TS but callable at runtime.
        (flow as any).session = {
          accountId: nearAccountId,
          deviceNumber,
          nearPublicKey: 'ed25519:temp',
          credential: dummyCredential,
          phase: 'idle',
          createdAt: Date.now(),
          expiresAt: Date.now() + 60_000,
        };

        const deterministicKeysResult = {
          nearPublicKey: 'ed25519:pk-device2',
          credential: dummyCredential,
        };

        await (flow as any).storeDeviceAuthenticator(deterministicKeysResult);

        // LinkDeviceFlow derives/stores the encrypted NEAR key earlier in the real flow.
        // For this regression, store a minimal entry so signing can proceed immediately.
        await nearKeysDB.storeKeyMaterialV2({
          profileId,
          deviceNumber: 2,
          chainId,
          keyKind: 'local_sk_encrypted_v1',
          algorithm: 'ed25519',
          publicKey: 'ed25519:pk-device2',
          wrapKeySalt: 'wrapKeySalt-b64u',
          payload: {
            encryptedSk: 'ciphertext-b64u',
            chacha20NonceB64u: 'nonce-b64u',
          },
          timestamp: Date.now(),
          schemaVersion: 1,
        });

        const last = await clientDB.getLastSelectedNearAccountProjection();
        const deviceFromHelper = await getLastLoggedInDeviceNumber(nearAccountId, clientDB);
        const key = await nearKeysDB.getKeyMaterialV2(profileId, deviceFromHelper, chainId, 'local_sk_encrypted_v1');
        const authenticators = await clientDB.listNearAuthenticators(nearAccountId);

        // Exercise the signing handler path up to and including the IndexedDB lookups.
        // We stub the SecureConfirm confirmation and worker response so the test stays deterministic
        // and focuses on "link device → immediate sign" state wiring.
        const signingCtx: any = {
          indexedDB: {
            clientDB,
            nearKeysDB,
            getNearLocalKeyMaterialV2First: async (accountId: string, deviceNum: number) => {
              const normalizedAccountId = String(accountId || '').trim().toLowerCase();
              const localProfileId = `legacy-near:${normalizedAccountId}`;
              const localChainId = normalizedAccountId.endsWith('.testnet') ? 'near:testnet' : 'near:mainnet';
              const row = await nearKeysDB.getKeyMaterialV2(
                localProfileId,
                deviceNum,
                localChainId,
                'local_sk_encrypted_v1',
              );
              if (!row) return null;
              const wrapKeySalt = String(row.wrapKeySalt || '').trim();
              const encryptedSk = String((row.payload as any)?.encryptedSk || '').trim();
              const chacha20NonceB64u = String((row.payload as any)?.chacha20NonceB64u || '').trim();
              if (!wrapKeySalt || !encryptedSk || !chacha20NonceB64u) return null;
              return {
                nearAccountId: accountId,
                deviceNumber: deviceNum,
                kind: 'local_near_sk_v3' as const,
                publicKey: row.publicKey,
                wrapKeySalt,
                encryptedSk,
                chacha20NonceB64u,
                timestamp: row.timestamp,
              };
            },
            getNearThresholdKeyMaterialV2First: async () => null,
          },
          nonceManager: { initializeUser: () => {} },
          touchIdPrompt: { getRpId: () => 'example.localhost' },
          relayerUrl: 'https://relay-server.localhost',
          postWrapKeySeedToSigner: () => {},
          secureConfirmWorkerManager: {
            confirmAndPrepareSigningSession: async () => ({
              intentDigest: 'intent',
              transactionContext: {
                nearPublicKeyStr: 'ed25519:pk-device2',
                nextNonce: '1',
                txBlockHeight: '1',
                txBlockHash: 'blockhash',
                accessKeyInfo: { nonce: 0 },
              },
              credential: dummyCredential,
            }),
          },
          requestWorkerOperation: async () => ({
            type: WorkerResponseType.SignTransactionsWithActionsSuccess,
            payload: {
              success: true,
              signedTransactions: [
                { transaction: {}, signature: {}, borshBytes: new Uint8Array([1]) },
              ],
              logs: [],
            },
          }),
          sendMessage: async () => ({
            type: WorkerResponseType.SignTransactionsWithActionsSuccess,
            payload: {
              success: true,
              signedTransactions: [
                { transaction: {}, signature: {}, borshBytes: new Uint8Array([1]) },
              ],
              logs: [],
            },
          }),
        };

        const signed = await signTransactionsWithActions({
          ctx: signingCtx,
          transactions: [
            {
              receiverId: nearAccountId,
              actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
            },
          ],
          rpcCall: { nearAccountId },
          signerMode: { mode: 'local-signer' },
          sessionId: 'linkdevice-regression-string-device',
        });

        return {
          success: true,
          lastUser: last ? { nearAccountId: last.nearAccountId, deviceNumber: last.deviceNumber } : null,
          deviceFromHelper,
          hasEncryptedKey: key?.keyKind === 'local_sk_encrypted_v1' && !!(key?.payload as any)?.encryptedSk,
          authenticatorCount: Array.isArray(authenticators) ? authenticators.length : 0,
          signedCount: Array.isArray(signed) ? signed.length : 0,
        } as const;
      } catch (error: any) {
        return { success: false, error: error?.message || String(error) } as const;
      }
    }, { paths: IMPORT_PATHS });

    if (!result.success) {
      if (handleInfrastructureErrors(result)) return;
      expect(result.success, result.error || 'unknown error').toBe(true);
      return;
    }

    expect(result.lastUser?.nearAccountId).toBe('linkdev2.w3a-v1.testnet');
    expect(result.lastUser?.deviceNumber).toBe(2);
    expect(result.deviceFromHelper).toBe(2);
    expect(result.hasEncryptedKey).toBe(true);
    expect(result.authenticatorCount).toBeGreaterThan(0);
    expect(result.signedCount).toBe(1);
  });
});
