import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  clientDB: '/sdk/esm/core/IndexedDBManager/passkeyClientDB.js',
  nearKeysDB: '/sdk/esm/core/IndexedDBManager/passkeyNearKeysDB.js',
  indexedDB: '/sdk/esm/core/IndexedDBManager/index.js',
  getDeviceNumber: '/sdk/esm/core/signing/webauthn/device/getDeviceNumber.js',
} as const;

test.describe('DB multichain migration + saga', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('post-migration invariants quarantine invalid rows', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { PasskeyClientDBManager } = await import(paths.clientDB);
      const dbName = `PasskeyClientDB-quarantine-${Date.now()}-${Math.random().toString(16).slice(2)}`;

      const dbm = new PasskeyClientDBManager();
      dbm.setDbName(dbName);
      const raw = await (dbm as any).getDB();
      const now = Date.now();

      // Seed intentionally invalid V2 rows that should be quarantined.
      await raw.put('chainAccounts', {
        profileId: 'missing-profile',
        chainId: 'near:testnet',
        accountAddress: 'alice.testnet',
        accountModel: 'near-native',
        createdAt: now,
        updatedAt: now,
      });
      await raw.put('accountSigners', {
        profileId: 'missing-profile',
        chainId: 'near:testnet',
        accountAddress: 'alice.testnet',
        signerId: 'signer-invalid',
        signerSlot: 0,
        signerType: 'passkey',
        status: 'active',
        addedAt: now,
        updatedAt: now,
      });
      await raw.put('appState', {
        key: 'lastProfileState',
        value: {
          profileId: 'missing-profile',
          deviceNumber: 1,
        },
      });

      // Force migration rerun so invariant step executes after seeding invalid rows.
      await dbm.setAppState('migration.dbMultichainSchema.v1', {
        status: 'failed',
        schemaVersion: 0,
        startedAt: now - 1000,
        counts: {},
        checkpoints: {},
      });
      await dbm.setAppState('migration.dbMultichainSchema.v1.checkpoints', {});
      await (dbm as any).runMigrationsIfNeeded(raw);

      const migrationState = await dbm.getAppState('migration.dbMultichainSchema.v1');
      const quarantineRows = await raw.getAll('migrationQuarantine');
      const invalidChain = await raw.get('chainAccounts', ['missing-profile', 'near:testnet', 'alice.testnet']);
      const invalidSigner = await raw.get('accountSigners', ['near:testnet', 'alice.testnet', 'signer-invalid']);
      const invalidLastProfileState = await raw.get('appState', 'lastProfileState');
      const quarantineReasons = (quarantineRows || []).map((row: any) => String(row.reason || ''));

      return {
        migrationStatus: migrationState?.status || null,
        invariantChecked: Number(migrationState?.counts?.invariantRowsChecked || 0),
        invariantViolations: Number(migrationState?.counts?.invariantViolationsFound || 0),
        quarantinedCount: Number(migrationState?.counts?.invariantRowsQuarantined || 0),
        quarantineStoreCount: Array.isArray(quarantineRows) ? quarantineRows.length : 0,
        removedInvalidChain: !invalidChain,
        removedInvalidSigner: !invalidSigner,
        removedInvalidLastProfileState: !invalidLastProfileState,
        quarantineReasons,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.migrationStatus).toBe('completed');
    expect(result.invariantChecked).toBeGreaterThan(0);
    expect(result.invariantViolations).toBeGreaterThanOrEqual(3);
    expect(result.quarantinedCount).toBeGreaterThanOrEqual(3);
    expect(result.quarantineStoreCount).toBeGreaterThanOrEqual(3);
    expect(result.removedInvalidChain).toBe(true);
    expect(result.removedInvalidSigner).toBe(true);
    expect(result.removedInvalidLastProfileState).toBe(true);
    expect(result.quarantineReasons.some((reason: string) => reason.includes('lastProfileState'))).toBe(true);
  });

  test('secureConfirm/worker-facing lookups are V2-first', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { PasskeyClientDBManager } = await import(paths.clientDB);
      const { PasskeyNearKeysDBManager } = await import(paths.nearKeysDB);
      const { getLastLoggedInDeviceNumber } = await import(paths.getDeviceNumber);
      const now = Date.now();

      const clientDb = new PasskeyClientDBManager();
      const clientDbName = `PasskeyClientDB-v2first-${now}-${Math.random().toString(16).slice(2)}`;
      clientDb.setDbName(clientDbName);
      const rawClient = await (clientDb as any).getDB();

      await rawClient.put('profiles', {
        profileId: 'legacy-near:alice.testnet',
        defaultDeviceNumber: 9,
        passkeyCredential: { id: 'v2-cred', rawId: 'v2-raw' },
        createdAt: now,
        updatedAt: now,
      });
      await rawClient.put('chainAccounts', {
        profileId: 'legacy-near:alice.testnet',
        chainId: 'near:testnet',
        accountAddress: 'alice.testnet',
        accountModel: 'near-native',
        isPrimary: true,
        createdAt: now,
        updatedAt: now,
        legacyNearAccountId: 'alice.testnet',
      });
      await rawClient.put('accountSigners', {
        profileId: 'legacy-near:alice.testnet',
        chainId: 'near:testnet',
        accountAddress: 'alice.testnet',
        signerId: 'v2-raw',
        signerSlot: 9,
        signerType: 'passkey',
        status: 'active',
        addedAt: now,
        updatedAt: now,
        metadata: {
          clientNearPublicKey: 'ed25519:v2pk',
          passkeyCredentialId: 'v2-cred',
          passkeyCredentialRawId: 'v2-raw',
        },
      });
      await rawClient.put('profileAuthenticators', {
        profileId: 'legacy-near:alice.testnet',
        deviceNumber: 9,
        credentialId: 'v2-cred',
        credentialPublicKey: new Uint8Array([1, 2, 3]),
        registered: '',
        syncedAt: '',
      });

      // Legacy rows intentionally conflict; V2 should be preferred by read paths.
      await rawClient.put('users', {
        nearAccountId: 'alice.testnet',
        deviceNumber: 1,
        clientNearPublicKey: 'ed25519:legacy-pk',
        passkeyCredential: { id: 'legacy-cred', rawId: 'legacy-raw' },
        version: 2,
        registeredAt: now,
        lastLogin: now,
        lastUpdated: now,
      });
      await rawClient.put('authenticators', {
        nearAccountId: 'alice.testnet',
        deviceNumber: 1,
        credentialId: 'legacy-cred',
        credentialPublicKey: new Uint8Array([9]),
        registered: '',
        syncedAt: '',
      });
      await rawClient.put('appState', {
        key: 'lastUserAccountId',
        value: {
          accountId: 'alice.testnet',
          deviceNumber: 1,
        },
      });
      await clientDb.setLastProfileState({
        profileId: 'legacy-near:alice.testnet',
        deviceNumber: 9,
      });

      const auths = await clientDb.listNearAuthenticators('alice.testnet');
      const resolvedDeviceNumber = await getLastLoggedInDeviceNumber('alice.testnet', clientDb);

      const nearKeys = new PasskeyNearKeysDBManager();
      const nearKeyDbName = `PasskeyNearKeys-v2first-${now}-${Math.random().toString(16).slice(2)}`;
      nearKeys.setDbName(nearKeyDbName);
      await nearKeys.storeKeyMaterialV2({
        profileId: 'legacy-near:alice.testnet',
        deviceNumber: 9,
        chainId: 'near:testnet',
        keyKind: 'local_sk_encrypted_v1',
        algorithm: 'ed25519',
        publicKey: 'ed25519:v2-k',
        wrapKeySalt: 'v2-salt',
        payload: {
          encryptedSk: 'v2-encrypted',
          chacha20NonceB64u: 'v2-nonce',
        },
        timestamp: now,
        schemaVersion: 1,
      });

      const key = await nearKeys.getKeyMaterialV2(
        'legacy-near:alice.testnet',
        9,
        'near:testnet',
        'local_sk_encrypted_v1',
      );
      const rawNear = await (nearKeys as any).getDB();
      const rawStored = await rawNear.get('keyMaterialV2', [
        'legacy-near:alice.testnet',
        9,
        'near:testnet',
        'local_sk_encrypted_v1',
      ]);
      const storedPayload = (rawStored?.payload && typeof rawStored.payload === 'object')
        ? rawStored.payload
        : null;
      const storedEnvelope = (rawStored?.payloadEnvelope && typeof rawStored.payloadEnvelope === 'object')
        ? rawStored.payloadEnvelope
        : null;

      return {
        authenticatorIds: auths.map((a: any) => a.credentialId),
        resolvedDeviceNumber,
        selectedEncryptedSk: String((key?.payload as any)?.encryptedSk || '') || null,
        storedHasLegacyCiphertextField: !!(storedPayload && Object.prototype.hasOwnProperty.call(storedPayload, 'encryptedSk')),
        storedEnvelopeAlg: String(storedEnvelope?.alg || '') || null,
        storedEnvelopeCiphertext: String(storedEnvelope?.ciphertext || '') || null,
        storedEnvelopeNonce: String(storedEnvelope?.nonce || '') || null,
        storedEnvelopeAadProfileId: String((storedEnvelope as any)?.aad?.profileId || '') || null,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.authenticatorIds).toEqual(['v2-cred']);
    expect(result.resolvedDeviceNumber).toBe(9);
    expect(result.selectedEncryptedSk).toBe('v2-encrypted');
    expect(result.storedHasLegacyCiphertextField).toBe(false);
    expect(result.storedEnvelopeAlg).toBe('chacha20poly1305-b64u-v1');
    expect(result.storedEnvelopeCiphertext).toBe('v2-encrypted');
    expect(result.storedEnvelopeNonce).toBe('v2-nonce');
    expect(result.storedEnvelopeAadProfileId).toBe('legacy-near:alice.testnet');
  });

  test('V2-first lookup helpers do not fallback to legacy key store rows', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { IndexedDBManager } = await import(paths.indexedDB);
      const now = Date.now();
      const manager = IndexedDBManager;
      manager.clientDB.setDisabled(false);
      manager.nearKeysDB.setDisabled(false);
      manager.clientDB.setDbName(`PasskeyClientDB-v2-only-lookup-${now}-${Math.random().toString(16).slice(2)}`);
      manager.nearKeysDB.setDbName(`PasskeyNearKeys-v2-only-lookup-${now}-${Math.random().toString(16).slice(2)}`);
      (manager as any)._initialized = false;
      await manager.initialize();

      await manager.upsertProfile({
        profileId: 'legacy-near:alice.testnet',
        defaultDeviceNumber: 1,
        passkeyCredential: { id: 'cred-a', rawId: 'raw-a' },
      });
      await manager.upsertChainAccount({
        profileId: 'legacy-near:alice.testnet',
        chainId: 'near:testnet',
        accountAddress: 'alice.testnet',
        accountModel: 'near-native',
        isPrimary: true,
      });

      const rawNear = await (manager.nearKeysDB as any).getDB();
      const legacyStorePresent = !!rawNear?.objectStoreNames?.contains?.('keyMaterial');

      const before = await manager.getNearLocalKeyMaterialV2First('alice.testnet', 1);
      await manager.storeNearLocalKeyMaterialV2({
        nearAccountId: 'alice.testnet',
        deviceNumber: 1,
        publicKey: 'ed25519:v2-only',
        wrapKeySalt: 'v2-salt',
        encryptedSk: 'v2-encrypted',
        chacha20NonceB64u: 'v2-nonce',
        timestamp: now + 1,
      });
      const after = await manager.getNearLocalKeyMaterialV2First('alice.testnet', 1);

      return {
        legacyStorePresent,
        beforeEncryptedSk: before?.encryptedSk || null,
        afterEncryptedSk: after?.encryptedSk || null,
        afterPublicKey: after?.publicKey || null,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.legacyStorePresent).toBe(false);
    expect(result.beforeEncryptedSk).toBeNull();
    expect(result.afterEncryptedSk).toBe('v2-encrypted');
    expect(result.afterPublicKey).toBe('ed25519:v2-only');
  });

  test('NEAR V2 write helpers enforce explicit target invariants', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { IndexedDBManager } = await import(paths.indexedDB);
      const now = Date.now();
      const manager = IndexedDBManager;
      manager.clientDB.setDisabled(false);
      manager.nearKeysDB.setDisabled(false);
      manager.clientDB.setDbName(`PasskeyClientDB-v2-write-invariants-${now}-${Math.random().toString(16).slice(2)}`);
      manager.nearKeysDB.setDbName(`PasskeyNearKeys-v2-write-invariants-${now}-${Math.random().toString(16).slice(2)}`);
      (manager as any)._initialized = false;
      await manager.initialize();

      const captureError = async (fn: () => Promise<void>): Promise<string> => {
        try {
          await fn();
          return '';
        } catch (error: any) {
          return String(error?.message || error || '');
        }
      };

      const baseLocal = {
        nearAccountId: 'alice.testnet',
        deviceNumber: 1,
        publicKey: 'ed25519:pk-a',
        wrapKeySalt: 'salt-a',
        encryptedSk: 'encrypted-a',
        chacha20NonceB64u: 'nonce-a',
        timestamp: now,
      };

      const missingChainIdError = await captureError(async () => {
        await manager.storeNearLocalKeyMaterialV2({
          ...baseLocal,
          profileId: 'legacy-near:alice.testnet',
        });
      });

      const missingProfileIdError = await captureError(async () => {
        await manager.storeNearLocalKeyMaterialV2({
          ...baseLocal,
          chainId: 'near:testnet',
        });
      });

      const nonNearChainError = await captureError(async () => {
        await manager.storeNearLocalKeyMaterialV2({
          ...baseLocal,
          profileId: 'legacy-near:alice.testnet',
          chainId: 'eip155:1',
        });
      });

      await manager.upsertProfile({
        profileId: 'legacy-near:alice.testnet',
        defaultDeviceNumber: 1,
        passkeyCredential: { id: 'cred-a', rawId: 'raw-a' },
      });
      await manager.upsertChainAccount({
        profileId: 'legacy-near:alice.testnet',
        chainId: 'near:testnet',
        accountAddress: 'alice.testnet',
        accountModel: 'near-native',
        isPrimary: true,
      });

      const mappedProfileMismatchError = await captureError(async () => {
        await manager.storeNearLocalKeyMaterialV2({
          ...baseLocal,
          profileId: 'legacy-near:other.testnet',
          chainId: 'near:testnet',
        });
      });

      const missingMappedProfileError = await captureError(async () => {
        await manager.storeNearThresholdKeyMaterialV2({
          nearAccountId: 'bob.testnet',
          deviceNumber: 1,
          publicKey: 'ed25519:bob-threshold',
          relayerKeyId: 'relayer-key-1',
          clientShareDerivation: 'prf_first_v1',
          timestamp: now + 10,
        });
      });

      return {
        missingChainIdError,
        missingProfileIdError,
        nonNearChainError,
        mappedProfileMismatchError,
        missingMappedProfileError,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.missingChainIdError).toContain('profileId and chainId must be provided together');
    expect(result.missingProfileIdError).toContain('profileId and chainId must be provided together');
    expect(result.nonNearChainError).toContain('require near:* chainId');
    expect(result.mappedProfileMismatchError).toContain('mismatches mapped profile');
    expect(result.missingMappedProfileError).toContain('Missing V2 profile/account mapping');
  });

  test('legacy NEAR key APIs are removed and V2 APIs remain available', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { PasskeyNearKeysDBManager } = await import(paths.nearKeysDB);
      const now = Date.now();
      const db = new PasskeyNearKeysDBManager();
      db.setDbName(`PasskeyNearKeys-legacy-cutover-${now}-${Math.random().toString(16).slice(2)}`);

      await db.storeKeyMaterialV2({
        profileId: 'legacy-near:alice.testnet',
        deviceNumber: 1,
        chainId: 'near:testnet',
        keyKind: 'local_sk_encrypted_v1',
        algorithm: 'ed25519',
        publicKey: 'ed25519:v2',
        wrapKeySalt: 'v2-salt',
        payload: {
          encryptedSk: 'v2-encrypted',
          chacha20NonceB64u: 'v2-nonce',
        },
        timestamp: now + 1,
        schemaVersion: 1,
      });

      const v2 = await db.getKeyMaterialV2(
        'legacy-near:alice.testnet',
        1,
        'near:testnet',
        'local_sk_encrypted_v1',
      );

      return {
        hasStoreKeyMaterial: typeof (db as any).storeKeyMaterial === 'function',
        hasGetLocalKeyMaterial: typeof (db as any).getLocalKeyMaterial === 'function',
        hasGetThresholdKeyMaterial: typeof (db as any).getThresholdKeyMaterial === 'function',
        v2PublicKey: v2?.publicKey || null,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.hasStoreKeyMaterial).toBe(false);
    expect(result.hasGetLocalKeyMaterial).toBe(false);
    expect(result.hasGetThresholdKeyMaterial).toBe(false);
    expect(result.v2PublicKey).toBe('ed25519:v2');
  });

  test('write invariants enforce capability matrix + lifecycle transitions', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { PasskeyClientDBManager } = await import(paths.clientDB);
      const now = Date.now();
      const dbm = new PasskeyClientDBManager();
      dbm.setDbName(`PasskeyClientDB-write-invariants-${now}-${Math.random().toString(16).slice(2)}`);

      await dbm.upsertProfile({
        profileId: 'profile-1',
        defaultDeviceNumber: 1,
        passkeyCredential: { id: 'cred-1', rawId: 'raw-1' },
      });

      await dbm.upsertChainAccount({
        profileId: 'profile-1',
        chainId: 'eip155:1',
        accountAddress: '0xabc',
        accountModel: 'eoa',
        isPrimary: true,
      });

      await dbm.upsertChainAccount({
        profileId: 'profile-1',
        chainId: 'eip155:1',
        accountAddress: '0xdef',
        accountModel: 'eoa',
        isPrimary: true,
      });

      await dbm.upsertAccountSigner({
        profileId: 'profile-1',
        chainId: 'eip155:1',
        accountAddress: '0xabc',
        signerId: 'primary-eoa',
        signerSlot: 1,
        signerType: 'passkey',
        status: 'active',
        mutation: { routeThroughOutbox: false },
      });

      const captureCode = async (fn: () => Promise<void>): Promise<string | null> => {
        try {
          await fn();
          return null;
        } catch (error: any) {
          return String(error?.code || '');
        }
      };

      const secondSignerCode = await captureCode(async () => {
        await dbm.upsertAccountSigner({
          profileId: 'profile-1',
          chainId: 'eip155:1',
          accountAddress: '0xabc',
          signerId: 'secondary-eoa',
          signerSlot: 2,
          signerType: 'passkey',
          status: 'active',
          mutation: { routeThroughOutbox: false },
        });
      });

      const sessionSignerCode = await captureCode(async () => {
        await dbm.upsertAccountSigner({
          profileId: 'profile-1',
          chainId: 'eip155:1',
          accountAddress: '0xdef',
          signerId: 'session-eoa',
          signerSlot: 1,
          signerType: 'session',
          status: 'active',
          mutation: { routeThroughOutbox: false },
        });
      });

      const invalidTransitionCode = await captureCode(async () => {
        await dbm.setAccountSignerStatus({
          chainId: 'eip155:1',
          accountAddress: '0xabc',
          signerId: 'primary-eoa',
          status: 'pending',
          mutation: { routeThroughOutbox: false },
        });
      });

      await dbm.setAccountSignerStatus({
        chainId: 'eip155:1',
        accountAddress: '0xabc',
        signerId: 'primary-eoa',
        status: 'revoked',
        mutation: { routeThroughOutbox: false },
      });

      const reactivationCode = await captureCode(async () => {
        await dbm.setAccountSignerStatus({
          chainId: 'eip155:1',
          accountAddress: '0xabc',
          signerId: 'primary-eoa',
          status: 'active',
          mutation: { routeThroughOutbox: false },
        });
      });

      const invalidLastProfileStateCode = await captureCode(async () => {
        await dbm.setLastProfileState({
          profileId: 'unknown-profile',
          deviceNumber: 1,
        });
      });

      const raw = await (dbm as any).getDB();
      const byProfileChain = await raw
        .transaction('chainAccounts', 'readonly')
        .store
        .index('profileId_chainId')
        .getAll(['profile-1', 'eip155:1']);
      const primaryCount = (byProfileChain || []).filter((row: any) => !!row?.isPrimary).length;

      return {
        secondSignerCode,
        sessionSignerCode,
        invalidTransitionCode,
        reactivationCode,
        invalidLastProfileStateCode,
        primaryCount,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.secondSignerCode).toBe('MULTI_SIGNER_NOT_SUPPORTED');
    expect(result.sessionSignerCode).toBe('SESSION_SIGNER_NOT_SUPPORTED');
    expect(result.invalidTransitionCode).toBe('INVALID_SIGNER_STATUS_TRANSITION');
    expect(result.reactivationCode).toBe('INVALID_SIGNER_STATUS_TRANSITION');
    expect(result.invalidLastProfileStateCode).toBe('INVALID_LAST_PROFILE_STATE');
    expect(result.primaryCount).toBe(1);
  });

  test('outbox + cross-db saga repair converges NEAR and EVM/Tempo signer ops', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { IndexedDBManager } = await import(paths.indexedDB);
      const now = Date.now();
      const manager = IndexedDBManager;
      manager.clientDB.setDisabled(false);
      manager.nearKeysDB.setDisabled(false);
      manager.clientDB.setDbName(`PasskeyClientDB-saga-${now}-${Math.random().toString(16).slice(2)}`);
      manager.nearKeysDB.setDbName(`PasskeyNearKeys-saga-${now}-${Math.random().toString(16).slice(2)}`);
      (manager as any)._initialized = false;
      await manager.initialize();

      const profileId = 'legacy-near:alice.testnet';
      await manager.upsertProfile({
        profileId,
        defaultDeviceNumber: 1,
        passkeyCredential: { id: 'pc', rawId: 'pc-raw' },
      });
      await manager.upsertChainAccount({
        profileId,
        chainId: 'near:testnet',
        accountAddress: 'alice.testnet',
        accountModel: 'near-native',
        isPrimary: true,
      });
      await manager.upsertChainAccount({
        profileId,
        chainId: 'tempo:mainnet',
        accountAddress: 'tempo:alice',
        accountModel: 'tempo-native',
      });
      await manager.upsertChainAccount({
        profileId,
        chainId: 'eip155:1',
        accountAddress: '0xabc',
        accountModel: 'erc4337',
      });

      await manager.upsertAccountSigner({
        profileId,
        chainId: 'near:testnet',
        accountAddress: 'alice.testnet',
        signerId: 'near-signer',
        signerSlot: 1,
        signerType: 'passkey',
        status: 'pending',
      });
      await manager.upsertAccountSigner({
        profileId,
        chainId: 'tempo:mainnet',
        accountAddress: 'tempo:alice',
        signerId: 'tempo-signer',
        signerSlot: 2,
        signerType: 'threshold',
        status: 'pending',
      });
      await manager.upsertAccountSigner({
        profileId,
        chainId: 'eip155:1',
        accountAddress: '0xabc',
        signerId: 'evm-signer',
        signerSlot: 3,
        signerType: 'passkey',
        status: 'pending',
      });

      // Only NEAR key exists initially.
      await manager.storeKeyMaterialV2({
        profileId,
        deviceNumber: 1,
        chainId: 'near:testnet',
        keyKind: 'local_sk_encrypted_v1',
        algorithm: 'ed25519',
        publicKey: 'ed25519:pk-near',
        payload: { encryptedSk: 'near', chacha20NonceB64u: 'nonce-near' },
        wrapKeySalt: 'salt-near',
        timestamp: now,
        schemaVersion: 1,
      });

      const firstRepair = await manager.repairSignerMutationSagas({ limit: 50 });
      const nearSignerAfterFirst = await manager.getAccountSigner({
        chainId: 'near:testnet',
        accountAddress: 'alice.testnet',
        signerId: 'near-signer',
      });
      const tempoSignerAfterFirst = await manager.getAccountSigner({
        chainId: 'tempo:mainnet',
        accountAddress: 'tempo:alice',
        signerId: 'tempo-signer',
      });
      const evmSignerAfterFirst = await manager.getAccountSigner({
        chainId: 'eip155:1',
        accountAddress: '0xabc',
        signerId: 'evm-signer',
      });

      // Add remaining keys so failed outbox rows can recover.
      await manager.storeKeyMaterialV2({
        profileId,
        deviceNumber: 2,
        chainId: 'tempo:mainnet',
        keyKind: 'threshold_share_v1',
        algorithm: 'secp256k1',
        publicKey: 'tempo-pub',
        payload: { share: 'tempo-share' },
        timestamp: now + 1,
        schemaVersion: 1,
      });
      await manager.storeKeyMaterialV2({
        profileId,
        deviceNumber: 3,
        chainId: 'eip155:1',
        keyKind: 'local_sk_encrypted_v1',
        algorithm: 'webauthn-p256',
        publicKey: 'evm-pub',
        payload: { encryptedSk: 'evm', chacha20NonceB64u: 'nonce-evm' },
        wrapKeySalt: 'salt-evm',
        timestamp: now + 2,
        schemaVersion: 1,
      });

      await manager.clientDB.setSignerOperationStatus({
        opId: 'missing-op-id',
        status: 'queued',
      }).catch(() => undefined);

      const secondRepair = await manager.repairSignerMutationSagas({ limit: 50, now: now + 60_000 });
      const nearSignerAfterSecond = await manager.getAccountSigner({
        chainId: 'near:testnet',
        accountAddress: 'alice.testnet',
        signerId: 'near-signer',
      });
      const tempoSignerAfterSecond = await manager.getAccountSigner({
        chainId: 'tempo:mainnet',
        accountAddress: 'tempo:alice',
        signerId: 'tempo-signer',
      });
      const evmSignerAfterSecond = await manager.getAccountSigner({
        chainId: 'eip155:1',
        accountAddress: '0xabc',
        signerId: 'evm-signer',
      });

      const ops = await manager.listSignerOperations({
        statuses: ['queued', 'submitted', 'failed', 'confirmed', 'dead-letter'],
        dueBefore: now + 120_000,
        limit: 100,
      });
      const opStatusBySigner = Object.fromEntries(
        ops.map((row: any) => [String(row.signerId), String(row.status)]),
      );

      return {
        firstRepair,
        secondRepair,
        nearStatusFirst: nearSignerAfterFirst?.status || null,
        tempoStatusFirst: tempoSignerAfterFirst?.status || null,
        evmStatusFirst: evmSignerAfterFirst?.status || null,
        nearStatusSecond: nearSignerAfterSecond?.status || null,
        tempoStatusSecond: tempoSignerAfterSecond?.status || null,
        evmStatusSecond: evmSignerAfterSecond?.status || null,
        opStatusBySigner,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.firstRepair.scanned).toBeGreaterThanOrEqual(3);
    expect(result.nearStatusFirst).toBe('active');
    expect(result.tempoStatusFirst).toBe('pending');
    expect(result.evmStatusFirst).toBe('pending');

    expect(result.secondRepair.scanned).toBeGreaterThanOrEqual(2);
    expect(result.nearStatusSecond).toBe('active');
    expect(result.tempoStatusSecond).toBe('active');
    expect(result.evmStatusSecond).toBe('active');
    expect(result.opStatusBySigner['near-signer']).toBe('confirmed');
    expect(result.opStatusBySigner['tempo-signer']).toBe('confirmed');
    expect(result.opStatusBySigner['evm-signer']).toBe('confirmed');
  });
});
