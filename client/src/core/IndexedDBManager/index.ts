export { PasskeyClientDBManager, DBConstraintError } from './passkeyClientDB';
export { PasskeyNearKeysDBManager } from './passkeyNearKeysDB';

export type {
  ClientUserData,
  UserPreferences,
  ClientAuthenticatorData,
  ProfileAuthenticatorRecord,
  IndexedDBEvent,
  LastProfileState,
  DerivedAddressRecord,
  RecoveryEmailRecord,
  ProfileId,
  ChainId,
  AccountAddress,
  SignerId,
  AccountRef,
  MigrationQuarantineRecord,
  ProfileRecord,
  ChainAccountRecord,
  AccountSignerRecord,
  AccountModelCapabilities,
  AccountSignerStatus,
  DBConstraintErrorCode,
  SignerOperationStatus,
  SignerMutationOptions,
  SignerOpOutboxRecord,
  DerivedAddressV2Record,
  RecoveryEmailV2Record,
  UpsertProfileInput,
  UpsertChainAccountInput,
  UpsertAccountSignerInput,
  EnqueueSignerOperationInput,
} from './passkeyClientDB';

export type {
  PasskeyNearKeyMaterial,
  LocalNearSkV3Material,
  ThresholdEd25519_2p_V1Material,
  PasskeyNearKeyMaterialKind,
  ClientShareDerivation,
  PasskeyChainKeyMaterialV2,
  PasskeyChainKeyKind,
  PasskeyChainKeyAlgorithm,
  PasskeyChainKeyPayloadEnvelope,
  PasskeyChainKeyPayloadEnvelopeAAD,
} from './passkeyNearKeysDB';

import { AccountId } from '../types/accountIds';
import {
  buildThresholdEd25519Participants2pV1,
  parseThresholdEd25519ParticipantsV1,
} from '../../../../shared/src/threshold/participants';

// === SINGLETON INSTANCES ===
import { PasskeyClientDBManager } from './passkeyClientDB';
import {
  PasskeyNearKeysDBManager,
  type ClientShareDerivation,
  type LocalNearSkV3Material,
  type PasskeyChainKeyAlgorithm,
  type PasskeyChainKeyKind,
  type PasskeyChainKeyMaterialV2,
  type ThresholdEd25519_2p_V1Material,
} from './passkeyNearKeysDB';

// Export singleton instances for backward compatibility with existing code
export const passkeyClientDB = new PasskeyClientDBManager();
export const passkeyNearKeysDB = new PasskeyNearKeysDBManager();

export type IndexedDBMode = 'legacy' | 'wallet' | 'disabled';

function inferNearChainCandidates(nearAccountId: string): string[] {
  const normalized = String(nearAccountId || '').trim().toLowerCase();
  return normalized.endsWith('.testnet')
    ? ['near:testnet', 'near:mainnet']
    : ['near:mainnet', 'near:testnet'];
}

const DB_CONFIG_BY_MODE: Record<IndexedDBMode, { clientDbName: string; nearKeysDbName: string; disabled: boolean }> = {
  legacy: { clientDbName: 'PasskeyClientDB', nearKeysDbName: 'PasskeyNearKeys', disabled: false },
  wallet: { clientDbName: 'PasskeyClientDB', nearKeysDbName: 'PasskeyNearKeys', disabled: false },
  // When running the SDK on the app origin with a wallet iframe configured, we disable IndexedDB entirely
  // to ensure no SDK tables are created and nothing can accidentally persist there.
  disabled: { clientDbName: 'PasskeyClientDB', nearKeysDbName: 'PasskeyNearKeys', disabled: true },
};

let configured: { mode: IndexedDBMode; clientDbName: string; nearKeysDbName: string; disabled: boolean } | null = null;

/**
 * Configure IndexedDB database names for the current runtime.
 *
 * Call this once, early (before any IndexedDB access).
 * - Wallet iframe host should use `mode: 'wallet'`.
 * - App origin should use `mode: 'disabled'` when wallet-iframe mode is enabled.
 * - Non-iframe apps should use `mode: 'legacy'`.
 */
export function configureIndexedDB(args: { mode: IndexedDBMode }): { clientDbName: string; nearKeysDbName: string } {
  const mode = args?.mode;
  const next = DB_CONFIG_BY_MODE[mode];
  if (!next) {
    throw new Error(`[IndexedDBManager] Unknown IndexedDBMode: ${String(mode)}`);
  }

  if (configured) {
    const isSame =
      configured.clientDbName === next.clientDbName
      && configured.nearKeysDbName === next.nearKeysDbName
      && configured.disabled === next.disabled;
    if (!isSame) {
      console.warn('[IndexedDBManager] configureIndexedDB called multiple times; ignoring subsequent configuration', {
        configured,
        requested: next,
      });
    }
    return { clientDbName: configured.clientDbName, nearKeysDbName: configured.nearKeysDbName };
  }

  configured = { mode, ...next };
  passkeyClientDB.setDbName(next.clientDbName);
  passkeyNearKeysDB.setDbName(next.nearKeysDbName);
  passkeyClientDB.setDisabled(next.disabled);
  passkeyNearKeysDB.setDisabled(next.disabled);
  return { clientDbName: configured.clientDbName, nearKeysDbName: configured.nearKeysDbName };
}

export function getIndexedDBNames(): { clientDbName: string; nearKeysDbName: string } {
  return configured || {
    clientDbName: passkeyClientDB.getDbName(),
    nearKeysDbName: passkeyNearKeysDB.getDbName(),
  };
}

/**
 * Unified IndexedDB interface providing access to both databases
 * This allows centralized access while maintaining separation of concerns
 */
export class UnifiedIndexedDBManager {
  public readonly clientDB: PasskeyClientDBManager;
  public readonly nearKeysDB: PasskeyNearKeysDBManager;
  private _initialized = false;

  constructor() {
    this.clientDB = passkeyClientDB;
    this.nearKeysDB = passkeyNearKeysDB;
  }

  /**
   * Initialize both databases proactively
   * This ensures both databases are created and ready for use
   */
  async initialize(): Promise<void> {
    if (this._initialized) {
      return;
    }

    try {
      if (this.clientDB.isDisabled() || this.nearKeysDB.isDisabled()) {
        this._initialized = true;
        return;
      }
      // Initialize both databases by calling a simple operation
      // This will trigger the getDB() method in both managers and ensure databases are created
      await Promise.all([
        this.clientDB.getAppState('_init_check'),
        this.nearKeysDB.getKeyMaterialV2(
          '_init_check',
          1,
          'near:testnet',
          'local_sk_encrypted_v1',
        )
      ]);

      try {
        await this.repairSignerMutationSagas({ limit: 64 });
      } catch (error) {
        console.warn('IndexedDB saga repair failed during initialize:', error);
      }

      this._initialized = true;
    } catch (error) {
      console.warn('Failed to initialize IndexedDB databases:', error);
      // Don't throw - allow the SDK to continue working, databases will be initialized on first use
    }
  }

  /**
   * Check if databases have been initialized
   */
  get isInitialized(): boolean {
    return this._initialized;
  }

  private mapV2LocalNearKey(
    nearAccountId: AccountId,
    deviceNumber: number,
    rec: PasskeyChainKeyMaterialV2 | null,
  ): LocalNearSkV3Material | null {
    if (!rec) return null;
    const wrapKeySalt = String(rec.wrapKeySalt || '').trim();
    const encryptedSk = String((rec.payload as any)?.encryptedSk || '').trim();
    const chacha20NonceB64u = String((rec.payload as any)?.chacha20NonceB64u || '').trim();
    if (!wrapKeySalt || !encryptedSk || !chacha20NonceB64u) return null;
    return {
      nearAccountId,
      deviceNumber,
      kind: 'local_near_sk_v3',
      publicKey: rec.publicKey,
      wrapKeySalt,
      encryptedSk,
      chacha20NonceB64u,
      timestamp: rec.timestamp,
    };
  }

  private mapV2ThresholdNearKey(
    nearAccountId: AccountId,
    deviceNumber: number,
    rec: PasskeyChainKeyMaterialV2 | null,
  ): ThresholdEd25519_2p_V1Material | null {
    if (!rec) return null;
    const payload = (rec.payload || {}) as Record<string, unknown>;
    const relayerKeyId = String(payload.relayerKeyId || '').trim();
    const clientShareDerivation = String(payload.clientShareDerivation || '').trim() as
      | ClientShareDerivation
      | '';
    if (!relayerKeyId || !clientShareDerivation) return null;
    const participants =
      parseThresholdEd25519ParticipantsV1(payload.participants)
      || buildThresholdEd25519Participants2pV1({
        relayerKeyId,
        clientShareDerivation,
      });
    return {
      nearAccountId,
      deviceNumber,
      kind: 'threshold_ed25519_2p_v1',
      publicKey: rec.publicKey,
      ...(rec.wrapKeySalt ? { wrapKeySalt: rec.wrapKeySalt } : {}),
      relayerKeyId,
      clientShareDerivation,
      participants,
      timestamp: rec.timestamp,
    };
  }

  private async resolveNearProfileByAccount(
    nearAccountId: AccountId,
  ): Promise<{ profileId: string; chainId: string } | null> {
    const accountAddress = String(nearAccountId || '').trim().toLowerCase();
    if (!accountAddress) return null;

    for (const chainId of inferNearChainCandidates(accountAddress)) {
      const profile = await this.clientDB.getProfileByAccount(chainId, accountAddress).catch(
        () => null,
      );
      if (profile?.profileId) {
        return {
          profileId: String(profile.profileId).trim(),
          chainId,
        };
      }
    }
    return null;
  }

  async getNearLocalKeyMaterialV2First(
    nearAccountId: AccountId,
    deviceNumber: number,
  ): Promise<LocalNearSkV3Material | null> {
    const resolved = await this.resolveNearProfileByAccount(nearAccountId);
    if (!resolved?.profileId || !resolved.chainId) return null;
    const v2 = await this.nearKeysDB.getKeyMaterialV2(
      resolved.profileId,
      deviceNumber,
      resolved.chainId,
      'local_sk_encrypted_v1',
    );
    return this.mapV2LocalNearKey(nearAccountId, deviceNumber, v2);
  }

  async getNearThresholdKeyMaterialV2First(
    nearAccountId: AccountId,
    deviceNumber: number,
  ): Promise<ThresholdEd25519_2p_V1Material | null> {
    const resolved = await this.resolveNearProfileByAccount(nearAccountId);
    if (!resolved?.profileId || !resolved.chainId) return null;
    const v2 = await this.nearKeysDB.getKeyMaterialV2(
      resolved.profileId,
      deviceNumber,
      resolved.chainId,
      'threshold_share_v1',
    );
    return this.mapV2ThresholdNearKey(nearAccountId, deviceNumber, v2);
  }

  private async storeNearKeyMaterialV2(input: {
    nearAccountId: AccountId;
    deviceNumber: number;
    keyKind: PasskeyChainKeyKind;
    algorithm?: PasskeyChainKeyAlgorithm;
    publicKey: string;
    signerId?: string;
    wrapKeySalt?: string;
    payload?: Record<string, unknown>;
    timestamp?: number;
    schemaVersion?: number;
    profileId?: string;
    chainId?: string;
  }): Promise<void> {
    const accountAddress = String(input.nearAccountId || '').trim().toLowerCase();
    if (!accountAddress) {
      throw new Error('IndexedDBManager: Missing nearAccountId for V2 key write');
    }
    if (!Number.isSafeInteger(input.deviceNumber) || input.deviceNumber < 1) {
      throw new Error('IndexedDBManager: Invalid deviceNumber for V2 key write');
    }
    const keyKind = String(input.keyKind || '').trim();
    if (!keyKind) {
      throw new Error('IndexedDBManager: Missing keyKind for V2 key write');
    }
    if (keyKind !== 'local_sk_encrypted_v1' && keyKind !== 'threshold_share_v1') {
      throw new Error(`IndexedDBManager: Unsupported NEAR keyKind for V2 key write: ${keyKind}`);
    }
    const algorithm = String(input.algorithm || 'ed25519').trim().toLowerCase();
    if (algorithm !== 'ed25519') {
      throw new Error(`IndexedDBManager: Unsupported NEAR key algorithm for V2 key write: ${algorithm}`);
    }
    const publicKey = String(input.publicKey || '').trim();
    if (!publicKey) {
      throw new Error('IndexedDBManager: Missing publicKey for V2 key write');
    }

    const explicitProfileId = String(input.profileId || '').trim();
    const explicitChainId = String(input.chainId || '').trim().toLowerCase();
    const hasExplicitProfileId = explicitProfileId.length > 0;
    const hasExplicitChainId = explicitChainId.length > 0;
    if (hasExplicitProfileId !== hasExplicitChainId) {
      throw new Error('IndexedDBManager: profileId and chainId must be provided together for explicit V2 key target writes');
    }

    const resolved = hasExplicitProfileId && hasExplicitChainId
      ? null
      : await this.resolveNearProfileByAccount(accountAddress as AccountId);
    const profileId = hasExplicitProfileId
      ? explicitProfileId
      : String(resolved?.profileId || '').trim();
    const chainId = hasExplicitChainId
      ? explicitChainId
      : String(resolved?.chainId || '').trim().toLowerCase();
    if (!profileId || !chainId) {
      throw new Error(
        `IndexedDBManager: Missing V2 profile/account mapping for NEAR account "${accountAddress}". `
        + 'Persist profile/account first or pass explicit profileId + chainId.',
      );
    }
    if (!chainId.startsWith('near:')) {
      throw new Error(`IndexedDBManager: NEAR key writes require near:* chainId, received "${chainId}"`);
    }

    if (hasExplicitProfileId && hasExplicitChainId) {
      const mapped = await this.clientDB.getProfileByAccount(chainId, accountAddress).catch(() => null);
      if (mapped?.profileId && String(mapped.profileId).trim() !== profileId) {
        throw new Error(
          `IndexedDBManager: Explicit V2 key target (${profileId}, ${chainId}, ${accountAddress}) mismatches mapped profile ${String(mapped.profileId).trim()}`,
        );
      }
    }

    await this.storeKeyMaterialV2({
      profileId,
      deviceNumber: input.deviceNumber,
      chainId,
      keyKind,
      algorithm,
      publicKey,
      ...(input.signerId ? { signerId: String(input.signerId).trim() } : {}),
      ...(input.wrapKeySalt ? { wrapKeySalt: String(input.wrapKeySalt).trim() } : {}),
      ...(input.payload ? { payload: input.payload } : {}),
      timestamp: typeof input.timestamp === 'number' ? input.timestamp : Date.now(),
      schemaVersion: Number.isSafeInteger(input.schemaVersion) && input.schemaVersion! >= 1
        ? input.schemaVersion!
        : 1,
    });
  }

  async storeNearLocalKeyMaterialV2(input: {
    nearAccountId: AccountId;
    deviceNumber: number;
    publicKey: string;
    encryptedSk: string;
    chacha20NonceB64u: string;
    wrapKeySalt: string;
    signerId?: string;
    timestamp?: number;
    schemaVersion?: number;
    profileId?: string;
    chainId?: string;
  }): Promise<void> {
    const wrapKeySalt = String(input.wrapKeySalt || '').trim();
    const encryptedSk = String(input.encryptedSk || '').trim();
    const chacha20NonceB64u = String(input.chacha20NonceB64u || '').trim();
    if (!wrapKeySalt || !encryptedSk || !chacha20NonceB64u) {
      throw new Error('IndexedDBManager: Missing encrypted local NEAR key fields for V2 key write');
    }

    await this.storeNearKeyMaterialV2({
      nearAccountId: input.nearAccountId,
      deviceNumber: input.deviceNumber,
      keyKind: 'local_sk_encrypted_v1',
      publicKey: input.publicKey,
      signerId: input.signerId,
      wrapKeySalt,
      payload: {
        encryptedSk,
        chacha20NonceB64u,
      },
      timestamp: input.timestamp,
      schemaVersion: input.schemaVersion,
      profileId: input.profileId,
      chainId: input.chainId,
    });
  }

  async storeNearThresholdKeyMaterialV2(input: {
    nearAccountId: AccountId;
    deviceNumber: number;
    publicKey: string;
    relayerKeyId: string;
    clientShareDerivation: ClientShareDerivation;
    participants?: ThresholdEd25519_2p_V1Material['participants'];
    wrapKeySalt?: string;
    signerId?: string;
    timestamp?: number;
    schemaVersion?: number;
    profileId?: string;
    chainId?: string;
  }): Promise<void> {
    const relayerKeyId = String(input.relayerKeyId || '').trim();
    const clientShareDerivation = String(input.clientShareDerivation || '').trim() as ClientShareDerivation;
    if (!relayerKeyId || !clientShareDerivation) {
      throw new Error('IndexedDBManager: Missing threshold NEAR key fields for V2 key write');
    }
    const participants =
      parseThresholdEd25519ParticipantsV1(input.participants)
      || buildThresholdEd25519Participants2pV1({
        relayerKeyId,
        clientShareDerivation,
      });

    await this.storeNearKeyMaterialV2({
      nearAccountId: input.nearAccountId,
      deviceNumber: input.deviceNumber,
      keyKind: 'threshold_share_v1',
      publicKey: input.publicKey,
      signerId: input.signerId,
      ...(input.wrapKeySalt ? { wrapKeySalt: String(input.wrapKeySalt).trim() } : {}),
      payload: {
        relayerKeyId,
        clientShareDerivation,
        participants,
      },
      timestamp: input.timestamp,
      schemaVersion: input.schemaVersion,
      profileId: input.profileId,
      chainId: input.chainId,
    });
  }

  async getLastProfileState(): Promise<import('./passkeyClientDB').LastProfileState | null> {
    return this.clientDB.getLastProfileState();
  }

  async setLastProfileState(
    state: import('./passkeyClientDB').LastProfileState | null
  ): Promise<void> {
    return this.clientDB.setLastProfileState(state);
  }

  // === V2 profile/account/signer convenience ===
  async getProfile(profileId: string): Promise<import('./passkeyClientDB').ProfileRecord | null> {
    return this.clientDB.getProfile(profileId);
  }

  async upsertProfile(input: import('./passkeyClientDB').UpsertProfileInput): Promise<import('./passkeyClientDB').ProfileRecord> {
    return this.clientDB.upsertProfile(input);
  }

  async upsertChainAccount(input: import('./passkeyClientDB').UpsertChainAccountInput): Promise<import('./passkeyClientDB').ChainAccountRecord> {
    return this.clientDB.upsertChainAccount(input);
  }

  async getProfileByAccount(chainId: string, accountAddress: string): Promise<import('./passkeyClientDB').ProfileRecord | null> {
    return this.clientDB.getProfileByAccount(chainId, accountAddress);
  }

  async upsertAccountSigner(input: import('./passkeyClientDB').UpsertAccountSignerInput): Promise<import('./passkeyClientDB').AccountSignerRecord> {
    return this.clientDB.upsertAccountSigner(input);
  }

  async listAccountSigners(
    args: { chainId: string; accountAddress: string; status?: import('./passkeyClientDB').AccountSignerStatus }
  ): Promise<import('./passkeyClientDB').AccountSignerRecord[]> {
    return this.clientDB.listAccountSigners(args);
  }

  async getAccountSigner(args: {
    chainId: string;
    accountAddress: string;
    signerId: string;
  }): Promise<import('./passkeyClientDB').AccountSignerRecord | null> {
    return this.clientDB.getAccountSigner(args);
  }

  async setAccountSignerStatus(args: {
    chainId: string;
    accountAddress: string;
    signerId: string;
    status: import('./passkeyClientDB').AccountSignerStatus;
    removedAt?: number;
    mutation?: import('./passkeyClientDB').SignerMutationOptions;
  }): Promise<import('./passkeyClientDB').AccountSignerRecord | null> {
    return this.clientDB.setAccountSignerStatus(args);
  }

  async enqueueSignerOperation(
    input: import('./passkeyClientDB').EnqueueSignerOperationInput
  ): Promise<import('./passkeyClientDB').SignerOpOutboxRecord> {
    return this.clientDB.enqueueSignerOperation(input);
  }

  async listSignerOperations(args?: {
    statuses?: import('./passkeyClientDB').SignerOperationStatus[];
    dueBefore?: number;
    limit?: number;
  }): Promise<import('./passkeyClientDB').SignerOpOutboxRecord[]> {
    return this.clientDB.listSignerOperations(args);
  }

  async setSignerOperationStatus(args: {
    opId: string;
    status: import('./passkeyClientDB').SignerOperationStatus;
    attemptDelta?: number;
    nextAttemptAt?: number;
    lastError?: string | null;
    txHash?: string | null;
  }): Promise<import('./passkeyClientDB').SignerOpOutboxRecord | null> {
    return this.clientDB.setSignerOperationStatus(args);
  }

  // === V2 key material convenience ===
  async storeKeyMaterialV2(input: import('./passkeyNearKeysDB').PasskeyChainKeyMaterialV2): Promise<void> {
    return this.nearKeysDB.storeKeyMaterialV2(input);
  }

  async getKeyMaterialV2(
    profileId: string,
    deviceNumber: number,
    chainId: string,
    keyKind: import('./passkeyNearKeysDB').PasskeyChainKeyKind
  ): Promise<import('./passkeyNearKeysDB').PasskeyChainKeyMaterialV2 | null> {
    return this.nearKeysDB.getKeyMaterialV2(profileId, deviceNumber, chainId, keyKind);
  }

  private computeSignerOpRetryDelayMs(nextAttemptCount: number): number {
    const bounded = Math.max(1, Math.min(nextAttemptCount, 8));
    return Math.min(5 * 60_000, 5_000 * Math.pow(2, bounded - 1));
  }

  async repairSignerMutationSagas(args?: {
    limit?: number;
    now?: number;
  }): Promise<{
    scanned: number;
    confirmed: number;
    failed: number;
    deadLettered: number;
  }> {
    const now = typeof args?.now === 'number' ? args.now : Date.now();
    const limit = Number.isSafeInteger(args?.limit) && Number(args?.limit) > 0
      ? Number(args?.limit)
      : 100;
    const summary = {
      scanned: 0,
      confirmed: 0,
      failed: 0,
      deadLettered: 0,
    };

    const ops = await this.clientDB.listSignerOperations({
      statuses: ['queued', 'submitted', 'failed'],
      dueBefore: now,
      limit,
    });

    for (const op of ops) {
      summary.scanned += 1;
      const payload = (op.payload || {}) as Record<string, unknown>;
      const signer = await this.clientDB.getAccountSigner({
        chainId: op.chainId,
        accountAddress: op.accountAddress,
        signerId: op.signerId,
      });
      const profileIdRaw = String(signer?.profileId || payload.profileId || '').trim();
      const signerSlotRaw = Number(payload.signerSlot ?? payload.deviceNumber ?? signer?.signerSlot);
      const signerSlot = Number.isSafeInteger(signerSlotRaw) && signerSlotRaw >= 1
        ? signerSlotRaw
        : null;

      const markFailed = async (reason: string): Promise<void> => {
        const nextAttemptCount = (op.attemptCount || 0) + 1;
        await this.clientDB.setSignerOperationStatus({
          opId: op.opId,
          status: 'failed',
          attemptDelta: 1,
          lastError: reason,
          nextAttemptAt: now + this.computeSignerOpRetryDelayMs(nextAttemptCount),
        });
        summary.failed += 1;
      };

      const markDeadLetter = async (reason: string): Promise<void> => {
        await this.clientDB.setSignerOperationStatus({
          opId: op.opId,
          status: 'dead-letter',
          lastError: reason,
          nextAttemptAt: now,
        });
        summary.deadLettered += 1;
      };

      const markConfirmed = async (): Promise<void> => {
        await this.clientDB.setSignerOperationStatus({
          opId: op.opId,
          status: 'confirmed',
          lastError: null,
          nextAttemptAt: now,
        });
        summary.confirmed += 1;
      };

      try {
        if (op.opType === 'add-signer' || op.opType === 'activate-recovery-signer') {
          if (!signer) {
            await markDeadLetter('Missing signer row for add-signer operation');
            continue;
          }
          if (signer.status === 'revoked') {
            await markDeadLetter('Cannot activate a revoked signer; create a new signer record');
            continue;
          }
          if (!profileIdRaw || signerSlot == null) {
            await markDeadLetter('Missing profileId/signerSlot metadata for add-signer operation');
            continue;
          }
          const keys = await this.nearKeysDB.listKeyMaterialV2ByProfileAndDevice(
            profileIdRaw,
            signerSlot,
            op.chainId,
          );
          if (keys.length === 0) {
            await markFailed('Missing key material for signer operation');
            continue;
          }
          if (signer.status !== 'active') {
            await this.clientDB.setAccountSignerStatus({
              chainId: op.chainId,
              accountAddress: op.accountAddress,
              signerId: op.signerId,
              status: 'active',
              mutation: { routeThroughOutbox: false },
            });
          }
          await markConfirmed();
          continue;
        }

        if (op.opType === 'revoke-signer') {
          if (signer) {
            if (signer.status !== 'revoked') {
              await this.clientDB.setAccountSignerStatus({
                chainId: op.chainId,
                accountAddress: op.accountAddress,
                signerId: op.signerId,
                status: 'revoked',
                removedAt: now,
                mutation: { routeThroughOutbox: false },
              });
            }
            if (profileIdRaw && signerSlot != null) {
              const keys = await this.nearKeysDB.listKeyMaterialV2ByProfileAndDevice(
                profileIdRaw,
                signerSlot,
                op.chainId,
              );
              for (const key of keys) {
                await this.nearKeysDB.deleteKeyMaterialV2(
                  key.profileId,
                  key.deviceNumber,
                  key.chainId,
                  key.keyKind,
                );
              }
            }
          }
          await markConfirmed();
          continue;
        }

        await markDeadLetter(`Unsupported signer operation type: ${String(op.opType || '')}`);
      } catch (error: any) {
        await markFailed(String(error?.message || error || 'Unknown saga repair error'));
      }
    }

    return summary;
  }
}

// Export singleton instance of unified manager
export const IndexedDBManager = new UnifiedIndexedDBManager();
