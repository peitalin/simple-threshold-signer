export { PasskeyClientDBManager, DBConstraintError } from './passkeyClientDB';
export { PasskeyNearKeysDBManager } from './passkeyNearKeysDB';
export { UnifiedIndexedDBManager } from './unifiedIndexedDBManager';
export { passkeyClientDB, passkeyNearKeysDB } from './singletons';

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

import { UnifiedIndexedDBManager } from './unifiedIndexedDBManager';
import { passkeyClientDB, passkeyNearKeysDB } from './singletons';

export type IndexedDBMode = 'legacy' | 'wallet' | 'disabled';

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

// Export singleton instance of unified manager
export const IndexedDBManager = new UnifiedIndexedDBManager({
  clientDB: passkeyClientDB,
  nearKeysDB: passkeyNearKeysDB,
});
