import type { IDBPDatabase } from 'idb';

export interface PasskeyClientDBConfig {
  dbName: string;
  dbVersion: number;
  userStore: string;
  appStateStore: string;
  authenticatorStore: string;
  profileAuthenticatorStore: string;
  profilesStore: string;
  chainAccountsStore: string;
  accountSignersStore: string;
  signerOpsOutboxStore: string;
  derivedAddressV2Store: string;
  recoveryEmailV2Store: string;
  migrationQuarantineStore: string;
}

export const SIGNER_OPS_OUTBOX_STATUS_NEXT_ATTEMPT_INDEX = 'status_nextAttemptAt' as const;
export const DERIVED_ADDRESS_LOOKUP_INDEX = 'profileId_sourceChainId_sourceAccountAddress_providerRef_path' as const;

export const DB_CONFIG: PasskeyClientDBConfig = {
  dbName: 'PasskeyClientDB',
  dbVersion: 22, // v22: add query indexes for due-op scans and derived-address lookups
  userStore: 'users',
  appStateStore: 'appState',
  authenticatorStore: 'authenticators',
  profileAuthenticatorStore: 'profileAuthenticators',
  profilesStore: 'profiles',
  chainAccountsStore: 'chainAccounts',
  accountSignersStore: 'accountSigners',
  signerOpsOutboxStore: 'signerOpsOutbox',
  derivedAddressV2Store: 'derivedAddressesV2',
  recoveryEmailV2Store: 'recoveryEmailsV2',
  migrationQuarantineStore: 'migrationQuarantine',
} as const;

export const LEGACY_LAST_USER_APP_STATE_KEY = 'lastUserAccountId' as const;
export const LEGACY_DERIVED_ADDRESS_STORE = 'derivedAddresses' as const;
export const LEGACY_RECOVERY_EMAIL_STORE = 'recoveryEmails' as const;
export const LAST_PROFILE_STATE_APP_STATE_KEY = 'lastProfileState' as const;
export const DB_MULTICHAIN_MIGRATION_STATE_KEY = 'migration.dbMultichainSchema.v1' as const;
export const DB_MULTICHAIN_MIGRATION_LOCK_KEY = 'migration.dbMultichainSchema.v1.lock' as const;
export const DB_MULTICHAIN_MIGRATION_CHECKPOINTS_KEY = 'migration.dbMultichainSchema.v1.checkpoints' as const;
export const DB_MULTICHAIN_MIGRATION_LOCK_NAME = 'passkey-client-db-multichain-migration-v1' as const;
export const DB_MULTICHAIN_MIGRATION_LOCK_TTL_MS = 2 * 60_000;
export const DB_MULTICHAIN_MIGRATION_HEARTBEAT_INTERVAL_MS = 5_000;
export const DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION = 5 as const;
export const LEGACY_NEAR_PROFILE_PREFIX = 'legacy-near' as const;

const LEGACY_CLIENT_STORES_TO_DROP = [
  DB_CONFIG.userStore,
  DB_CONFIG.authenticatorStore,
  LEGACY_DERIVED_ADDRESS_STORE,
  LEGACY_RECOVERY_EMAIL_STORE,
] as const;

export function upgradePasskeyClientDBSchema(
  db: IDBPDatabase,
  oldVersion: number,
  transaction: any,
): void {
  if (!db.objectStoreNames.contains(DB_CONFIG.appStateStore)) {
    db.createObjectStore(DB_CONFIG.appStateStore, { keyPath: 'key' });
  }
  {
    const profileAuthenticators = !db.objectStoreNames.contains(DB_CONFIG.profileAuthenticatorStore)
      ? db.createObjectStore(DB_CONFIG.profileAuthenticatorStore, {
        keyPath: ['profileId', 'deviceNumber', 'credentialId'],
      })
      : transaction.objectStore(DB_CONFIG.profileAuthenticatorStore);
    try { profileAuthenticators.createIndex('profileId', 'profileId', { unique: false }); } catch {}
    try { profileAuthenticators.createIndex('credentialId', 'credentialId', { unique: false }); } catch {}
    try {
      profileAuthenticators.createIndex(
        'profileId_credentialId',
        ['profileId', 'credentialId'],
        { unique: false },
      );
    } catch {}
    try {
      profileAuthenticators.createIndex(
        'profileId_deviceNumber',
        ['profileId', 'deviceNumber'],
        { unique: false },
      );
    } catch {}
  }

  {
    const profiles = !db.objectStoreNames.contains(DB_CONFIG.profilesStore)
      ? db.createObjectStore(DB_CONFIG.profilesStore, { keyPath: 'profileId' })
      : transaction.objectStore(DB_CONFIG.profilesStore);
    try { profiles.createIndex('updatedAt', 'updatedAt', { unique: false }); } catch {}
  }

  {
    const chainAccounts = !db.objectStoreNames.contains(DB_CONFIG.chainAccountsStore)
      ? db.createObjectStore(DB_CONFIG.chainAccountsStore, {
        keyPath: ['profileId', 'chainId', 'accountAddress'],
      })
      : transaction.objectStore(DB_CONFIG.chainAccountsStore);
    try { chainAccounts.createIndex('profileId', 'profileId', { unique: false }); } catch {}
    try { chainAccounts.createIndex('chainId', 'chainId', { unique: false }); } catch {}
    try {
      chainAccounts.createIndex(
        'chainId_accountAddress',
        ['chainId', 'accountAddress'],
        { unique: false },
      );
    } catch {}
    try {
      chainAccounts.createIndex(
        'profileId_chainId',
        ['profileId', 'chainId'],
        { unique: false },
      );
    } catch {}
  }

  {
    const accountSigners = !db.objectStoreNames.contains(DB_CONFIG.accountSignersStore)
      ? db.createObjectStore(DB_CONFIG.accountSignersStore, {
        keyPath: ['chainId', 'accountAddress', 'signerId'],
      })
      : transaction.objectStore(DB_CONFIG.accountSignersStore);
    try { accountSigners.createIndex('profileId', 'profileId', { unique: false }); } catch {}
    try {
      accountSigners.createIndex(
        'profileId_chainId',
        ['profileId', 'chainId'],
        { unique: false },
      );
    } catch {}
    try {
      accountSigners.createIndex(
        'chainId_accountAddress',
        ['chainId', 'accountAddress'],
        { unique: false },
      );
    } catch {}
    try {
      accountSigners.createIndex(
        'chainId_accountAddress_status',
        ['chainId', 'accountAddress', 'status'],
        { unique: false },
      );
    } catch {}
  }

  {
    const signerOpsOutbox = !db.objectStoreNames.contains(DB_CONFIG.signerOpsOutboxStore)
      ? db.createObjectStore(DB_CONFIG.signerOpsOutboxStore, { keyPath: 'opId' })
      : transaction.objectStore(DB_CONFIG.signerOpsOutboxStore);
    try { signerOpsOutbox.createIndex('status', 'status', { unique: false }); } catch {}
    try { signerOpsOutbox.createIndex('nextAttemptAt', 'nextAttemptAt', { unique: false }); } catch {}
    try {
      signerOpsOutbox.createIndex(
        SIGNER_OPS_OUTBOX_STATUS_NEXT_ATTEMPT_INDEX,
        ['status', 'nextAttemptAt'],
        { unique: false },
      );
    } catch {}
    try { signerOpsOutbox.createIndex('idempotencyKey', 'idempotencyKey', { unique: true }); } catch {}
    try {
      signerOpsOutbox.createIndex(
        'chainId_accountAddress',
        ['chainId', 'accountAddress'],
        { unique: false },
      );
    } catch {}
  }

  {
    const derivedAddressV2 = !db.objectStoreNames.contains(DB_CONFIG.derivedAddressV2Store)
      ? db.createObjectStore(DB_CONFIG.derivedAddressV2Store, {
        keyPath: ['profileId', 'sourceChainId', 'sourceAccountAddress', 'targetChainId', 'path'],
      })
      : transaction.objectStore(DB_CONFIG.derivedAddressV2Store);
    try { derivedAddressV2.createIndex('profileId', 'profileId', { unique: false }); } catch {}
    try {
      derivedAddressV2.createIndex(
        'profileId_targetChainId',
        ['profileId', 'targetChainId'],
        { unique: false },
      );
    } catch {}
    try {
      derivedAddressV2.createIndex(
        'sourceChainId_sourceAccountAddress',
        ['sourceChainId', 'sourceAccountAddress'],
        { unique: false },
      );
    } catch {}
    try {
      derivedAddressV2.createIndex(
        DERIVED_ADDRESS_LOOKUP_INDEX,
        ['profileId', 'sourceChainId', 'sourceAccountAddress', 'providerRef', 'path'],
        { unique: false },
      );
    } catch {}
  }

  {
    const recoveryEmailV2 = !db.objectStoreNames.contains(DB_CONFIG.recoveryEmailV2Store)
      ? db.createObjectStore(DB_CONFIG.recoveryEmailV2Store, {
        keyPath: ['profileId', 'hashHex'],
      })
      : transaction.objectStore(DB_CONFIG.recoveryEmailV2Store);
    try { recoveryEmailV2.createIndex('profileId', 'profileId', { unique: false }); } catch {}
  }

  {
    const quarantine = !db.objectStoreNames.contains(DB_CONFIG.migrationQuarantineStore)
      ? db.createObjectStore(DB_CONFIG.migrationQuarantineStore, {
        keyPath: 'quarantineId',
        autoIncrement: true,
      })
      : transaction.objectStore(DB_CONFIG.migrationQuarantineStore);
    try { quarantine.createIndex('sourceStore', 'sourceStore', { unique: false }); } catch {}
    try { quarantine.createIndex('detectedAt', 'detectedAt', { unique: false }); } catch {}
  }

  if (oldVersion < 21) {
    for (const storeName of LEGACY_CLIENT_STORES_TO_DROP) {
      if (db.objectStoreNames.contains(storeName)) {
        db.deleteObjectStore(storeName);
      }
    }
  }
}
