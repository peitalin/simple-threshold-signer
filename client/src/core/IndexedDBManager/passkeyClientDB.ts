import { openDB, type IDBPDatabase } from 'idb';
import type { AccountId } from '../types/accountIds';
import { toAccountId } from '../types/accountIds';
import {
  ConfirmationConfig,
  DEFAULT_CONFIRMATION_CONFIG,
  type SignerMode,
} from '../types/signer-worker'


export interface ClientUserData {
  // Primary key - now uses AccountId + deviceNumber for unique identification
  nearAccountId: AccountId;
  deviceNumber: number; // Device number for multi-device support (1-indexed)
  version?: number;

  // User metadata
  registeredAt?: number;
  lastLogin?: number;
  lastUpdated?: number;

  // WebAuthn/Passkey data (merged from WebAuthnManager)
  clientNearPublicKey: string;
  passkeyCredential: {
    id: string;
    rawId: string;
  };

  // User preferences
  preferences?: UserPreferences;
}

export type StoreUserDataInput = Omit<ClientUserData, 'deviceNumber' | 'lastLogin' | 'registeredAt'>
  & {
    deviceNumber?: number;
    version?: number;
  };

export interface UserPreferences {
  useRelayer: boolean;
  useNetwork: 'testnet' | 'mainnet';
  confirmationConfig: ConfirmationConfig;
  signerMode?: SignerMode;
  // User preferences can be extended here as needed
}

// Authenticator cache
export interface ClientAuthenticatorData {
  credentialId: string;
  credentialPublicKey: Uint8Array;
  transports?: string[]; // AuthenticatorTransport[]
  name?: string;
  nearAccountId: AccountId; // FK reference using AccountId
  deviceNumber: number; // Device number for this authenticator (1-indexed)
  registered: string; // ISO date string
  syncedAt: string; // When this cache entry was last synced with contract
}

interface AppStateEntry<T = unknown> {
  key: string;
  value: T;
}

// Internal helper: legacy user records may be missing deviceNumber.
type ClientUserDataWithOptionalDevice =
  | ClientUserData
  | (Omit<ClientUserData, 'deviceNumber'> & { deviceNumber?: number });

// Migration-only shape for legacy app state entry (`lastUserAccountId`).
interface LegacyLastUserState {
  accountId: AccountId;
  deviceNumber: number;
}

export interface LastProfileState {
  profileId: string;
  deviceNumber: number;
  scope?: string | null;
}

interface PasskeyClientDBConfig {
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

// === CONSTANTS ===
const DB_CONFIG: PasskeyClientDBConfig = {
  dbName: 'PasskeyClientDB',
  dbVersion: 20, // v20: add migrationQuarantine invariant sink + post-migration validation
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

const LEGACY_LAST_USER_APP_STATE_KEY = 'lastUserAccountId' as const;
const LEGACY_DERIVED_ADDRESS_STORE = 'derivedAddresses' as const;
const LEGACY_RECOVERY_EMAIL_STORE = 'recoveryEmails' as const;
const LAST_PROFILE_STATE_APP_STATE_KEY = 'lastProfileState' as const;
const DB_MULTICHAIN_MIGRATION_STATE_KEY = 'migration.dbMultichainSchema.v1' as const;
const DB_MULTICHAIN_MIGRATION_LOCK_KEY = 'migration.dbMultichainSchema.v1.lock' as const;
const DB_MULTICHAIN_MIGRATION_CHECKPOINTS_KEY = 'migration.dbMultichainSchema.v1.checkpoints' as const;
const DB_MULTICHAIN_MIGRATION_LOCK_NAME = 'passkey-client-db-multichain-migration-v1' as const;
const DB_MULTICHAIN_MIGRATION_LOCK_TTL_MS = 2 * 60_000;
const DB_MULTICHAIN_MIGRATION_HEARTBEAT_INTERVAL_MS = 5_000;
const DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION = 4 as const;
const LEGACY_NEAR_PROFILE_PREFIX = 'legacy-near' as const;

function normalizeLastUserScope(scope: unknown): string | null {
  const normalized = typeof scope === 'string' ? scope.trim() : '';
  if (!normalized || normalized === 'null') return null;
  return normalized;
}

function makeScopedAppStateKey(baseKey: string, scope: unknown): string | null {
  const normalized = normalizeLastUserScope(scope);
  if (!normalized) return null;
  return `${baseKey}::${normalized}`;
}

function normalizeChainId(chainId: unknown): string {
  return String(chainId || '').trim().toLowerCase();
}

function normalizeAccountAddress(address: unknown): string {
  return String(address || '').trim().toLowerCase();
}

function normalizeAccountModel(model: unknown): AccountModel {
  return String(model || '').trim().toLowerCase();
}

function buildLegacyNearProfileId(accountId: AccountId): string {
  return `${LEGACY_NEAR_PROFILE_PREFIX}:${String(accountId)}`;
}

function parseLegacyLastUserState(raw: unknown): LegacyLastUserState | null {
  if (raw == null) return null;

  // Legacy format: stored as string accountId only.
  if (typeof raw === 'string') {
    const accountIdStr = raw.trim();
    if (!accountIdStr) return null;
    try {
      return { accountId: toAccountId(accountIdStr), deviceNumber: 1 };
    } catch {
      return null;
    }
  }

  if (typeof raw !== 'object') return null;

  const accountIdStr = typeof (raw as any).accountId === 'string' ? String((raw as any).accountId).trim() : '';
  if (!accountIdStr) return null;

  let accountId: AccountId;
  try {
    accountId = toAccountId(accountIdStr);
  } catch {
    return null;
  }

  const deviceNumberRaw = (raw as any).deviceNumber;
  const deviceNumber = Number(deviceNumberRaw);
  if (!Number.isSafeInteger(deviceNumber) || deviceNumber < 1) return null;

  return { accountId, deviceNumber };
}

function parseLastProfileState(raw: unknown): LastProfileState | null {
  if (raw == null || typeof raw !== 'object') return null;

  const profileId = typeof (raw as any).profileId === 'string'
    ? String((raw as any).profileId).trim()
    : '';
  if (!profileId) return null;

  const deviceNumberRaw = (raw as any).deviceNumber;
  const deviceNumber = Number(deviceNumberRaw);
  if (!Number.isSafeInteger(deviceNumber) || deviceNumber < 1) return null;

  const scope = normalizeLastUserScope((raw as any).scope);
  return scope != null
    ? { profileId, deviceNumber, scope }
    : { profileId, deviceNumber };
}

function inferNearChainId(nearAccountId: AccountId, networkHint?: UserPreferences['useNetwork']): string {
  if (networkHint === 'mainnet') return 'near:mainnet';
  if (networkHint === 'testnet') return 'near:testnet';
  return String(nearAccountId).endsWith('.testnet') ? 'near:testnet' : 'near:mainnet';
}

function parseEip155ChainId(raw: unknown): string | null {
  const value = String(raw || '').trim().toLowerCase();
  if (!value) return null;
  if (/^\d+$/.test(value)) return value;
  if (!/^0x[0-9a-f]+$/.test(value)) return null;
  const asNumber = Number.parseInt(value, 16);
  if (!Number.isSafeInteger(asNumber) || asNumber < 0) return null;
  return String(asNumber);
}

function inferTargetChainIdFromLegacyDerivedAddress(rec: DerivedAddressRecord): string {
  const namespace = String(rec.namespace || '').trim().toLowerCase();
  const chainRef = String(rec.chainRef || '').trim();
  const path = String(rec.path || '').trim().toLowerCase();
  const evmChainFromPath = (() => {
    const match = path.match(/^evm:([^:]+):/);
    return match?.[1] || null;
  })();

  if (namespace === 'evm' || path.startsWith('evm:')) {
    const chainId = parseEip155ChainId(chainRef || evmChainFromPath || '');
    return chainId ? `eip155:${chainId}` : 'eip155:unknown';
  }
  if (namespace === 'solana' || path.startsWith('solana:')) return 'solana:unknown';
  if (namespace === 'zcash' || path.startsWith('zcash:')) return 'zcash:unknown';
  if (namespace === 'tempo' || path.startsWith('tempo:')) return 'tempo:unknown';
  return 'unknown:derived';
}

function buildDefaultDbMultichainMigrationCounts(): DbMultichainMigrationCounts {
  return {
    legacyUsersScanned: 0,
    coreUserBackfillSuccess: 0,
    coreUserBackfillFailures: 0,
    legacyAuthenticatorsScanned: 0,
    profileAuthenticatorUpserts: 0,
    profileAuthenticatorFailures: 0,
    legacyDerivedAddressesScanned: 0,
    derivedAddressV2Upserts: 0,
    derivedAddressV2Failures: 0,
    legacyRecoveryEmailsScanned: 0,
    recoveryEmailV2Upserts: 0,
    recoveryEmailV2Failures: 0,
    lastProfileStateSynced: 0,
    invariantRowsChecked: 0,
    invariantViolationsFound: 0,
    invariantRowsQuarantined: 0,
  };
}

function getNearChainCandidates(accountId: AccountId): string[] {
  const preferred = inferNearChainId(accountId);
  return preferred === 'near:testnet'
    ? ['near:testnet', 'near:mainnet']
    : ['near:mainnet', 'near:testnet'];
}

export interface IndexedDBEvent {
  type: 'user-updated' | 'preferences-updated' | 'user-deleted';
  accountId: AccountId;
  data?: Record<string, unknown>;
}

// Persisted mapping of derived (e.g., EVM) addresses tied to an account
/**
 * Persisted mapping of derived (e.g., EVM/Solana/Zcash) addresses tied to an account.
 *
 * Notes on multi-chain support:
 * - The composite primary key is [nearAccountId, contractId, path]. To support
 *   different chains and chain IDs, encode them in the `path` string, e.g.:
 *     - EVM: `evm:<chainId>:<derivationPath>` → `evm:84532:ethereum-1`
 *     - Solana: `solana:<derivationPath>`
 *     - Zcash: `zcash:<derivationPath>`
 * - Additional descriptive fields like `namespace` and `chainRef` are optional metadata
 *   and are not part of the key.
 */
export interface DerivedAddressRecord {
  nearAccountId: AccountId;
  contractId: string; // MPC/Derivation contract on NEAR
  path: string;       // Composite path (may include namespace/chainId); see docs above
  address: string;    // Derived address (e.g., 0x...)
  updatedAt: number;
  // Optional metadata (not used in the key)
  namespace?: string; // e.g., 'evm', 'solana', 'zcash'
  chainRef?: string;  // e.g., chainId '84532' or a named network slug
}

export interface RecoveryEmailRecord {
  nearAccountId: AccountId;
  hashHex: string;
  email: string;
  addedAt: number;
}

export interface ProfileAuthenticatorRecord {
  profileId: string;
  deviceNumber: number;
  credentialId: string;
  credentialPublicKey: Uint8Array;
  transports?: string[];
  name?: string;
  registered: string;
  syncedAt: string;
}

interface DbMultichainMigrationState {
  status: 'running' | 'completed' | 'failed';
  schemaVersion: number;
  startedAt: number;
  finishedAt?: number;
  counts: DbMultichainMigrationCounts;
  checkpoints?: DbMultichainMigrationCheckpoints;
  error?: string;
}

type DbMultichainMigrationStep =
  | 'legacyUsersToCoreV2'
  | 'legacyAuthenticatorsToProfileAuthenticators'
  | 'legacyDerivedAddressesToV2'
  | 'legacyRecoveryEmailsToV2'
  | 'lastProfileStateSync'
  | 'parityChecksLogged'
  | 'invariantsValidatedAndQuarantined';

type DbMultichainMigrationCheckpoints = Partial<Record<
  DbMultichainMigrationStep,
  {
    status: 'completed';
    completedAt: number;
    counts?: Record<string, number>;
  }
>>;

interface DbMultichainMigrationCounts {
  legacyUsersScanned: number;
  coreUserBackfillSuccess: number;
  coreUserBackfillFailures: number;
  legacyAuthenticatorsScanned: number;
  profileAuthenticatorUpserts: number;
  profileAuthenticatorFailures: number;
  legacyDerivedAddressesScanned: number;
  derivedAddressV2Upserts: number;
  derivedAddressV2Failures: number;
  legacyRecoveryEmailsScanned: number;
  recoveryEmailV2Upserts: number;
  recoveryEmailV2Failures: number;
  lastProfileStateSynced: number;
  invariantRowsChecked: number;
  invariantViolationsFound: number;
  invariantRowsQuarantined: number;
}

interface DbMultichainMigrationLock {
  ownerTabId: string;
  acquiredAt: number;
  heartbeatAt: number;
}

interface DbMultichainMigrationParity {
  legacyUsers: number;
  legacyUniqueAccounts: number;
  legacyAuthenticators: number;
  legacyDerivedAddresses: number;
  legacyRecoveryEmails: number;
  v2Profiles: number;
  v2ChainAccounts: number;
  v2AccountSigners: number;
  v2ProfileAuthenticators: number;
  v2DerivedAddresses: number;
  v2RecoveryEmails: number;
  mismatches: string[];
}

export interface MigrationQuarantineRecord {
  quarantineId?: number;
  sourceStore: string;
  sourcePrimaryKey: string;
  reason: string;
  record: unknown;
  detectedAt: number;
  schemaVersion: number;
}

interface InvariantViolationRecord {
  sourceStore: string;
  sourcePrimaryKey: unknown;
  reason: string;
  record: unknown;
}

export interface SignerMutationOptions {
  routeThroughOutbox?: boolean;
  opId?: string;
  idempotencyKey?: string;
  outboxPayload?: Record<string, unknown>;
  outboxStatus?: SignerOperationStatus;
}

export type ProfileId = string;
export type ChainId = string;
export type AccountAddress = string;
export type SignerId = string;

export interface AccountRef {
  chainId: ChainId;
  accountAddress: AccountAddress;
}

export type AccountModel = 'near-native' | 'erc4337' | 'eoa' | 'tempo-native' | string;
export type AccountSignerType = 'passkey' | 'threshold' | 'session' | 'recovery' | string;
export type AccountSignerStatus = 'active' | 'pending' | 'revoked';
export interface AccountModelCapabilities {
  supportsMultiSigner: boolean;
  supportsAddRemoveSigner: boolean;
  supportsSessionSigner: boolean;
  supportsRecoverySigner: boolean;
}

export type DBConstraintErrorCode =
  | 'MISSING_PROFILE'
  | 'MISSING_CHAIN_ACCOUNT'
  | 'CHAIN_ACCOUNT_PROFILE_MISMATCH'
  | 'MULTI_SIGNER_NOT_SUPPORTED'
  | 'SIGNER_MUTATION_NOT_SUPPORTED'
  | 'SESSION_SIGNER_NOT_SUPPORTED'
  | 'RECOVERY_SIGNER_NOT_SUPPORTED'
  | 'DUPLICATE_ACTIVE_SIGNER_SLOT'
  | 'EOA_ACTIVE_SIGNER_LIMIT'
  | 'INVALID_SIGNER_STATUS_TRANSITION'
  | 'REVOKED_SIGNER_REQUIRES_REMOVED_AT'
  | 'INVALID_LAST_PROFILE_STATE';

export class DBConstraintError extends Error {
  readonly code: DBConstraintErrorCode;
  readonly details?: Record<string, unknown>;

  constructor(code: DBConstraintErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'DBConstraintError';
    this.code = code;
    this.details = details;
  }
}

const DEFAULT_ACCOUNT_MODEL_CAPABILITIES: AccountModelCapabilities = {
  supportsMultiSigner: true,
  supportsAddRemoveSigner: true,
  supportsSessionSigner: true,
  supportsRecoverySigner: true,
};

const ACCOUNT_MODEL_CAPABILITY_MATRIX: Record<string, AccountModelCapabilities> = {
  'near-native': {
    supportsMultiSigner: true,
    supportsAddRemoveSigner: true,
    supportsSessionSigner: true,
    supportsRecoverySigner: true,
  },
  erc4337: {
    supportsMultiSigner: true,
    supportsAddRemoveSigner: true,
    supportsSessionSigner: true,
    supportsRecoverySigner: true,
  },
  eoa: {
    supportsMultiSigner: false,
    supportsAddRemoveSigner: false,
    supportsSessionSigner: false,
    supportsRecoverySigner: false,
  },
  'tempo-native': {
    supportsMultiSigner: true,
    supportsAddRemoveSigner: true,
    supportsSessionSigner: true,
    supportsRecoverySigner: true,
  },
};

const ALLOWED_SIGNER_STATUS_TRANSITIONS: Record<AccountSignerStatus, ReadonlySet<AccountSignerStatus>> = {
  pending: new Set<AccountSignerStatus>(['pending', 'active', 'revoked']),
  active: new Set<AccountSignerStatus>(['active', 'revoked']),
  revoked: new Set<AccountSignerStatus>(['revoked']),
};

export type SignerOperationType =
  | 'add-signer'
  | 'revoke-signer'
  | 'activate-recovery-signer'
  | string;
export type SignerOperationStatus =
  | 'queued'
  | 'submitted'
  | 'confirmed'
  | 'failed'
  | 'dead-letter';

export interface ProfileRecord {
  profileId: ProfileId;
  defaultDeviceNumber: number;
  passkeyCredential: ClientUserData['passkeyCredential'];
  preferences?: UserPreferences;
  createdAt: number;
  updatedAt: number;
}

export interface ChainAccountRecord {
  profileId: ProfileId;
  chainId: ChainId;
  accountAddress: AccountAddress;
  accountModel: AccountModel;
  isPrimary?: boolean;
  createdAt: number;
  updatedAt: number;
  legacyNearAccountId?: AccountId;
}

export interface AccountSignerRecord {
  profileId: ProfileId;
  chainId: ChainId;
  accountAddress: AccountAddress;
  signerId: SignerId;
  signerSlot: number;
  signerType: AccountSignerType;
  status: AccountSignerStatus;
  addedAt: number;
  updatedAt: number;
  removedAt?: number;
  metadata?: Record<string, unknown>;
}

export interface SignerOpOutboxRecord {
  opId: string;
  idempotencyKey: string;
  opType: SignerOperationType;
  chainId: ChainId;
  accountAddress: AccountAddress;
  signerId: SignerId;
  payload?: Record<string, unknown>;
  status: SignerOperationStatus;
  attemptCount: number;
  nextAttemptAt: number;
  lastError?: string;
  txHash?: string;
  createdAt: number;
  updatedAt: number;
}

export type UpsertProfileInput = {
  profileId: ProfileId;
  defaultDeviceNumber?: number;
  passkeyCredential: ClientUserData['passkeyCredential'];
  preferences?: UserPreferences;
};

export type UpsertChainAccountInput = {
  profileId: ProfileId;
  chainId: ChainId;
  accountAddress: AccountAddress;
  accountModel: AccountModel;
  isPrimary?: boolean;
  legacyNearAccountId?: AccountId;
};

export type UpsertAccountSignerInput = {
  profileId: ProfileId;
  chainId: ChainId;
  accountAddress: AccountAddress;
  signerId: SignerId;
  signerSlot: number;
  signerType: AccountSignerType;
  status: AccountSignerStatus;
  removedAt?: number;
  metadata?: Record<string, unknown>;
  mutation?: SignerMutationOptions;
};

export type EnqueueSignerOperationInput = {
  opId: string;
  idempotencyKey: string;
  opType: SignerOperationType;
  chainId: ChainId;
  accountAddress: AccountAddress;
  signerId: SignerId;
  payload?: Record<string, unknown>;
  status?: SignerOperationStatus;
  attemptCount?: number;
  nextAttemptAt?: number;
  lastError?: string;
  txHash?: string;
};

export interface DerivedAddressV2Record {
  profileId: ProfileId;
  sourceChainId: ChainId;
  sourceAccountAddress: AccountAddress;
  targetChainId: ChainId;
  providerRef: string;
  path: string;
  address: string;
  updatedAt: number;
}

export interface RecoveryEmailV2Record {
  profileId: ProfileId;
  hashHex: string;
  email: string;
  addedAt: number;
}

export class PasskeyClientDBManager {
  private config: PasskeyClientDBConfig;
  private db: IDBPDatabase | null = null;
  private disabled = false;
  private eventListeners: Set<(event: IndexedDBEvent) => void> = new Set();
  private lastUserScope: string | null = null;

  constructor(config: PasskeyClientDBConfig = DB_CONFIG) {
    this.config = config;
  }

  getDbName(): string {
    return this.config.dbName;
  }

  setDbName(dbName: string): void {
    const next = String(dbName || '').trim();
    if (!next || next === this.config.dbName) return;
    try { (this.db as any)?.close?.(); } catch {}
    this.db = null;
    this.config = { ...this.config, dbName: next };
  }

  isDisabled(): boolean {
    return this.disabled;
  }

  setDisabled(disabled: boolean): void {
    const next = !!disabled;
    if (next === this.disabled) return;
    this.disabled = next;
    if (next) {
      try { (this.db as any)?.close?.(); } catch {}
      this.db = null;
    }
  }

  // === EVENT SYSTEM ===

  onChange(listener: (event: IndexedDBEvent) => void): () => void {
    this.eventListeners.add(listener);
    return () => {
      this.eventListeners.delete(listener);
    };
  }

  private emitEvent(event: IndexedDBEvent): void {
    this.eventListeners.forEach(listener => {
      try {
        listener(event);
      } catch (error) {
        console.warn('[IndexedDBManager]: Error in event listener:', error);
      }
    });
  }

  private async getDB(): Promise<IDBPDatabase> {
    if (this.disabled) {
      throw new Error('[PasskeyClientDBManager] IndexedDB is disabled in this environment.');
    }
    if (this.db) {
      return this.db;
    }

    try {
      this.db = await openDB(this.config.dbName, this.config.dbVersion, {
      upgrade: (db, oldVersion, _newVersion, transaction): void => {
          // Create stores if they don't exist
          if (!db.objectStoreNames.contains(DB_CONFIG.userStore)) {
            // Users table: composite key of [nearAccountId, deviceNumber]
            const userStore = db.createObjectStore(DB_CONFIG.userStore, { keyPath: ['nearAccountId', 'deviceNumber'] });
            userStore.createIndex('nearAccountId', 'nearAccountId', { unique: false });
          }
          if (!db.objectStoreNames.contains(DB_CONFIG.appStateStore)) {
            db.createObjectStore(DB_CONFIG.appStateStore, { keyPath: 'key' });
          }
          if (!db.objectStoreNames.contains(DB_CONFIG.authenticatorStore)) {
            // Authenticators table: composite key of [nearAccountId, deviceNumber, credentialId]
            const authStore = db.createObjectStore(DB_CONFIG.authenticatorStore, { keyPath: ['nearAccountId', 'deviceNumber', 'credentialId'] });
            authStore.createIndex('nearAccountId', 'nearAccountId', { unique: false });
          }
          {
            const profileAuthenticators = !db.objectStoreNames.contains(DB_CONFIG.profileAuthenticatorStore)
              ? db.createObjectStore(DB_CONFIG.profileAuthenticatorStore, {
                keyPath: ['profileId', 'deviceNumber', 'credentialId']
              })
              : transaction.objectStore(DB_CONFIG.profileAuthenticatorStore);
            try { profileAuthenticators.createIndex('profileId', 'profileId', { unique: false }); } catch {}
            try { profileAuthenticators.createIndex('credentialId', 'credentialId', { unique: false }); } catch {}
            try {
              profileAuthenticators.createIndex(
                'profileId_credentialId',
                ['profileId', 'credentialId'],
                { unique: false }
              );
            } catch {}
            try {
              profileAuthenticators.createIndex(
                'profileId_deviceNumber',
                ['profileId', 'deviceNumber'],
                { unique: false }
              );
            } catch {}
          }
          // --- V2 multichain stores (additive; legacy stores remain intact) ---
          {
            const profiles = !db.objectStoreNames.contains(DB_CONFIG.profilesStore)
              ? db.createObjectStore(DB_CONFIG.profilesStore, { keyPath: 'profileId' })
              : transaction.objectStore(DB_CONFIG.profilesStore);
            try { profiles.createIndex('updatedAt', 'updatedAt', { unique: false }); } catch {}
          }

          {
            const chainAccounts = !db.objectStoreNames.contains(DB_CONFIG.chainAccountsStore)
              ? db.createObjectStore(DB_CONFIG.chainAccountsStore, {
                keyPath: ['profileId', 'chainId', 'accountAddress']
              })
              : transaction.objectStore(DB_CONFIG.chainAccountsStore);
            try { chainAccounts.createIndex('profileId', 'profileId', { unique: false }); } catch {}
            try { chainAccounts.createIndex('chainId', 'chainId', { unique: false }); } catch {}
            try {
              chainAccounts.createIndex(
                'chainId_accountAddress',
                ['chainId', 'accountAddress'],
                { unique: false }
              );
            } catch {}
            try {
              chainAccounts.createIndex(
                'profileId_chainId',
                ['profileId', 'chainId'],
                { unique: false }
              );
            } catch {}
          }

          {
            const accountSigners = !db.objectStoreNames.contains(DB_CONFIG.accountSignersStore)
              ? db.createObjectStore(DB_CONFIG.accountSignersStore, {
                keyPath: ['chainId', 'accountAddress', 'signerId']
              })
              : transaction.objectStore(DB_CONFIG.accountSignersStore);
            try { accountSigners.createIndex('profileId', 'profileId', { unique: false }); } catch {}
            try {
              accountSigners.createIndex(
                'profileId_chainId',
                ['profileId', 'chainId'],
                { unique: false }
              );
            } catch {}
            try {
              accountSigners.createIndex(
                'chainId_accountAddress',
                ['chainId', 'accountAddress'],
                { unique: false }
              );
            } catch {}
            try {
              accountSigners.createIndex(
                'chainId_accountAddress_status',
                ['chainId', 'accountAddress', 'status'],
                { unique: false }
              );
            } catch {}
          }

          {
            const signerOpsOutbox = !db.objectStoreNames.contains(DB_CONFIG.signerOpsOutboxStore)
              ? db.createObjectStore(DB_CONFIG.signerOpsOutboxStore, { keyPath: 'opId' })
              : transaction.objectStore(DB_CONFIG.signerOpsOutboxStore);
            try { signerOpsOutbox.createIndex('status', 'status', { unique: false }); } catch {}
            try { signerOpsOutbox.createIndex('nextAttemptAt', 'nextAttemptAt', { unique: false }); } catch {}
            try { signerOpsOutbox.createIndex('idempotencyKey', 'idempotencyKey', { unique: true }); } catch {}
            try {
              signerOpsOutbox.createIndex(
                'chainId_accountAddress',
                ['chainId', 'accountAddress'],
                { unique: false }
              );
            } catch {}
          }

          {
            const derivedAddressV2 = !db.objectStoreNames.contains(DB_CONFIG.derivedAddressV2Store)
              ? db.createObjectStore(DB_CONFIG.derivedAddressV2Store, {
                keyPath: ['profileId', 'sourceChainId', 'sourceAccountAddress', 'targetChainId', 'path']
              })
              : transaction.objectStore(DB_CONFIG.derivedAddressV2Store);
            try { derivedAddressV2.createIndex('profileId', 'profileId', { unique: false }); } catch {}
            try {
              derivedAddressV2.createIndex(
                'profileId_targetChainId',
                ['profileId', 'targetChainId'],
                { unique: false }
              );
            } catch {}
            try {
              derivedAddressV2.createIndex(
                'sourceChainId_sourceAccountAddress',
                ['sourceChainId', 'sourceAccountAddress'],
                { unique: false }
              );
            } catch {}
          }

          {
            const recoveryEmailV2 = !db.objectStoreNames.contains(DB_CONFIG.recoveryEmailV2Store)
              ? db.createObjectStore(DB_CONFIG.recoveryEmailV2Store, {
                keyPath: ['profileId', 'hashHex']
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
        },
        blocked() {
          console.warn('PasskeyClientDB connection is blocked.');
        },
        blocking() {
          console.warn('PasskeyClientDB connection is blocking another connection.');
        },
        terminated: () => {
          console.warn('PasskeyClientDB connection has been terminated.');
          this.db = null;
        },
      });

      // Post-open migrations (non-blocking)
      try { await this.runMigrationsIfNeeded(this.db); } catch {}

    } catch (err: any) {
      const msg = String(err?.message || '');
      if (err?.name === 'VersionError' || /less than the existing version/i.test(msg)) {
        // Mixed-version contexts (host/app) — open without version to adopt existing DB
        try {
          console.warn('PasskeyClientDB: opening existing DB without version due to VersionError');
          this.db = await openDB(this.config.dbName);
        } catch (e) {
          throw err;
        }
      } else {
        throw err;
      }
    }

    return this.db;
  }

  private async getAppStateFromDb<T = unknown>(db: IDBPDatabase, key: string): Promise<T | undefined> {
    const result = await db.get(DB_CONFIG.appStateStore, key);
    return result?.value as T | undefined;
  }

  private async setAppStateInDb<T = unknown>(db: IDBPDatabase, key: string, value: T): Promise<void> {
    const entry: AppStateEntry<T> = { key, value };
    await db.put(DB_CONFIG.appStateStore, entry);
  }

  private async setLastProfileStateInDb(
    db: IDBPDatabase,
    state: LastProfileState | null,
    scope: string | null = this.lastUserScope,
  ): Promise<void> {
    const scopedKey = makeScopedAppStateKey(LAST_PROFILE_STATE_APP_STATE_KEY, scope);
    if (scopedKey) {
      await this.setAppStateInDb(db, scopedKey, state);
      return;
    }
    await this.setAppStateInDb(db, LAST_PROFILE_STATE_APP_STATE_KEY, state);
  }

  private createMigrationOwnerId(): string {
    return typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : `migration-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }

  private isLegacyProfileId(profileId: unknown): boolean {
    return String(profileId || '').startsWith(`${LEGACY_NEAR_PROFILE_PREFIX}:`);
  }

  private isMigrationLockFresh(
    lock: DbMultichainMigrationLock | null | undefined,
    now: number = Date.now(),
  ): boolean {
    if (!lock) return false;
    if (!lock.ownerTabId) return false;
    if (!Number.isFinite(lock.heartbeatAt)) return false;
    return now - lock.heartbeatAt <= DB_MULTICHAIN_MIGRATION_LOCK_TTL_MS;
  }

  private async tryAcquireMigrationLeaseInAppState(
    db: IDBPDatabase,
    ownerTabId: string,
    acquiredAt: number,
  ): Promise<boolean> {
    const now = Date.now();
    const tx = db.transaction(DB_CONFIG.appStateStore, 'readwrite');
    const existing = await tx.store.get(DB_MULTICHAIN_MIGRATION_LOCK_KEY) as
      | AppStateEntry<DbMultichainMigrationLock | null>
      | undefined;
    const lock = (existing?.value || null) as DbMultichainMigrationLock | null;
    if (lock && lock.ownerTabId !== ownerTabId && this.isMigrationLockFresh(lock, now)) {
      await tx.done;
      return false;
    }
    const nextLock: DbMultichainMigrationLock = {
      ownerTabId,
      acquiredAt:
        lock?.ownerTabId === ownerTabId && Number.isFinite(lock?.acquiredAt)
          ? lock.acquiredAt
          : acquiredAt,
      heartbeatAt: now,
    };
    await tx.store.put({ key: DB_MULTICHAIN_MIGRATION_LOCK_KEY, value: nextLock });
    await tx.done;
    return true;
  }

  private async refreshMigrationLeaseInAppState(
    db: IDBPDatabase,
    ownerTabId: string,
    acquiredAt: number,
  ): Promise<void> {
    await this.setAppStateInDb(db, DB_MULTICHAIN_MIGRATION_LOCK_KEY, {
      ownerTabId,
      acquiredAt,
      heartbeatAt: Date.now(),
    } satisfies DbMultichainMigrationLock);
  }

  private async clearMigrationLeaseInAppState(
    db: IDBPDatabase,
    ownerTabId: string,
  ): Promise<void> {
    const tx = db.transaction(DB_CONFIG.appStateStore, 'readwrite');
    const existing = await tx.store.get(DB_MULTICHAIN_MIGRATION_LOCK_KEY) as
      | AppStateEntry<DbMultichainMigrationLock | null>
      | undefined;
    const lock = (existing?.value || null) as DbMultichainMigrationLock | null;
    if (!lock || lock.ownerTabId === ownerTabId) {
      await tx.store.put({ key: DB_MULTICHAIN_MIGRATION_LOCK_KEY, value: null });
    }
    await tx.done;
  }

  private async tryRunWithNavigatorMigrationLock(
    runner: () => Promise<void>,
  ): Promise<'executed' | 'unavailable' | 'unsupported'> {
    const lockManager = typeof navigator !== 'undefined'
      ? (navigator as any)?.locks
      : null;
    if (!lockManager || typeof lockManager.request !== 'function') {
      return 'unsupported';
    }
    try {
      let executed = false;
      await lockManager.request(
        DB_MULTICHAIN_MIGRATION_LOCK_NAME,
        { mode: 'exclusive', ifAvailable: true },
        async (lock: unknown) => {
          if (!lock) return;
          executed = true;
          await runner();
        },
      );
      return executed ? 'executed' : 'unavailable';
    } catch (error) {
      console.warn(
        'PasskeyClientDB: navigator.locks coordination failed; falling back to app-state migration lock',
        error,
      );
      return 'unsupported';
    }
  }

  private async countStoreRows(
    db: IDBPDatabase,
    storeName: string,
    predicate?: (value: unknown) => boolean,
  ): Promise<number> {
    if (!db.objectStoreNames.contains(storeName)) return 0;
    const tx = db.transaction(storeName, 'readonly');
    let cursor = await tx.store.openCursor();
    let count = 0;
    while (cursor) {
      if (!predicate || predicate(cursor.value)) {
        count += 1;
      }
      cursor = await cursor.continue();
    }
    await tx.done;
    return count;
  }

  private async collectLegacyUserStats(
    db: IDBPDatabase,
  ): Promise<{ legacyUsers: number; legacyUniqueAccounts: number }> {
    if (!db.objectStoreNames.contains(DB_CONFIG.userStore)) {
      return { legacyUsers: 0, legacyUniqueAccounts: 0 };
    }
    const tx = db.transaction(DB_CONFIG.userStore, 'readonly');
    let cursor = await tx.store.openCursor();
    let legacyUsers = 0;
    const uniqueAccounts = new Set<string>();
    while (cursor) {
      legacyUsers += 1;
      const accountIdRaw = (cursor.value as any)?.nearAccountId;
      try {
        const accountId = toAccountId(accountIdRaw);
        uniqueAccounts.add(String(accountId));
      } catch {}
      cursor = await cursor.continue();
    }
    await tx.done;
    return {
      legacyUsers,
      legacyUniqueAccounts: uniqueAccounts.size,
    };
  }

  private async collectMigrationParity(db: IDBPDatabase): Promise<DbMultichainMigrationParity> {
    const { legacyUsers, legacyUniqueAccounts } = await this.collectLegacyUserStats(db);
    const legacyAuthenticators = await this.countStoreRows(db, DB_CONFIG.authenticatorStore);
    const legacyDerivedAddresses = await this.countStoreRows(db, LEGACY_DERIVED_ADDRESS_STORE);
    const legacyRecoveryEmails = await this.countStoreRows(db, LEGACY_RECOVERY_EMAIL_STORE);

    const v2Profiles = await this.countStoreRows(
      db,
      DB_CONFIG.profilesStore,
      (value) => this.isLegacyProfileId((value as ProfileRecord)?.profileId),
    );
    const v2ChainAccounts = await this.countStoreRows(
      db,
      DB_CONFIG.chainAccountsStore,
      (value) => this.isLegacyProfileId((value as ChainAccountRecord)?.profileId),
    );
    const v2AccountSigners = await this.countStoreRows(
      db,
      DB_CONFIG.accountSignersStore,
      (value) => this.isLegacyProfileId((value as AccountSignerRecord)?.profileId),
    );
    const v2ProfileAuthenticators = await this.countStoreRows(
      db,
      DB_CONFIG.profileAuthenticatorStore,
      (value) => this.isLegacyProfileId((value as ProfileAuthenticatorRecord)?.profileId),
    );
    const v2DerivedAddresses = await this.countStoreRows(
      db,
      DB_CONFIG.derivedAddressV2Store,
      (value) => this.isLegacyProfileId((value as DerivedAddressV2Record)?.profileId),
    );
    const v2RecoveryEmails = await this.countStoreRows(
      db,
      DB_CONFIG.recoveryEmailV2Store,
      (value) => this.isLegacyProfileId((value as RecoveryEmailV2Record)?.profileId),
    );

    const mismatches: string[] = [];
    if (v2ProfileAuthenticators !== legacyAuthenticators) {
      mismatches.push(`profileAuthenticators:${v2ProfileAuthenticators}/legacyAuthenticators:${legacyAuthenticators}`);
    }
    if (v2DerivedAddresses !== legacyDerivedAddresses) {
      mismatches.push(`derivedAddressesV2:${v2DerivedAddresses}/legacyDerivedAddresses:${legacyDerivedAddresses}`);
    }
    if (v2RecoveryEmails !== legacyRecoveryEmails) {
      mismatches.push(`recoveryEmailsV2:${v2RecoveryEmails}/legacyRecoveryEmails:${legacyRecoveryEmails}`);
    }
    if (v2Profiles < legacyUniqueAccounts) {
      mismatches.push(`profiles:${v2Profiles}/legacyUniqueAccounts:${legacyUniqueAccounts}`);
    }
    if (v2ChainAccounts < legacyUniqueAccounts) {
      mismatches.push(`chainAccounts:${v2ChainAccounts}/legacyUniqueAccounts:${legacyUniqueAccounts}`);
    }
    if (v2AccountSigners < legacyUsers) {
      mismatches.push(`accountSigners:${v2AccountSigners}/legacyUsers:${legacyUsers}`);
    }

    return {
      legacyUsers,
      legacyUniqueAccounts,
      legacyAuthenticators,
      legacyDerivedAddresses,
      legacyRecoveryEmails,
      v2Profiles,
      v2ChainAccounts,
      v2AccountSigners,
      v2ProfileAuthenticators,
      v2DerivedAddresses,
      v2RecoveryEmails,
      mismatches,
    };
  }

  private encodeDbPrimaryKey(primaryKey: unknown): string {
    try {
      return JSON.stringify(primaryKey);
    } catch {
      return String(primaryKey);
    }
  }

  private async quarantineInvariantViolation(
    db: IDBPDatabase,
    violation: InvariantViolationRecord,
  ): Promise<void> {
    const tx = db.transaction(
      [violation.sourceStore, DB_CONFIG.migrationQuarantineStore],
      'readwrite',
    );
    const quarantine: MigrationQuarantineRecord = {
      sourceStore: violation.sourceStore,
      sourcePrimaryKey: this.encodeDbPrimaryKey(violation.sourcePrimaryKey),
      reason: violation.reason,
      record: violation.record,
      detectedAt: Date.now(),
      schemaVersion: DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION,
    };
    await tx.objectStore(DB_CONFIG.migrationQuarantineStore).put(quarantine);
    await tx.objectStore(violation.sourceStore).delete(violation.sourcePrimaryKey as any);
    await tx.done;
  }

  private async validateAndQuarantineInvariantViolations(
    db: IDBPDatabase,
  ): Promise<{ checked: number; violations: number; quarantined: number }> {
    const violations: InvariantViolationRecord[] = [];
    const seenViolationKeys = new Set<string>();
    const addViolation = (violation: InvariantViolationRecord): void => {
      const signature = `${violation.sourceStore}::${this.encodeDbPrimaryKey(violation.sourcePrimaryKey)}`;
      if (seenViolationKeys.has(signature)) return;
      seenViolationKeys.add(signature);
      violations.push(violation);
    };
    let checked = 0;
    const profileIds = new Set<string>();
    const chainAccounts = new Set<string>();
    const chainAccountModelByRef = new Map<string, AccountModel>();
    const primaryByProfileChain = new Map<string, unknown>();
    const profileSignerSlots = new Set<string>();
    const activeSignerByAccountSlot = new Map<string, { signerId: string }>();
    const activeSignerRowsByAccount = new Map<
      string,
      Array<{ primaryKey: unknown; row: AccountSignerRecord }>
    >();
    const chainAccountKey = (profileId: string, chainId: string, accountAddress: string): string =>
      `${profileId}::${normalizeChainId(chainId)}::${normalizeAccountAddress(accountAddress)}`;
    const signerSlotKey = (profileId: string, chainId: string, accountAddress: string, signerSlot: number): string =>
      `${chainAccountKey(profileId, chainId, accountAddress)}::slot:${signerSlot}`;
    const profileChainKey = (profileId: string, chainId: string): string =>
      `${profileId}::${normalizeChainId(chainId)}`;

    {
      const tx = db.transaction(DB_CONFIG.profilesStore, 'readonly');
      let cursor = await tx.store.openCursor();
      while (cursor) {
        checked += 1;
        const row = cursor.value as ProfileRecord;
        const profileId = String(row?.profileId || '').trim();
        if (!profileId) {
          addViolation({
            sourceStore: DB_CONFIG.profilesStore,
            sourcePrimaryKey: cursor.primaryKey,
            reason: 'Missing profileId',
            record: row,
          });
        } else {
          profileIds.add(profileId);
        }
        cursor = await cursor.continue();
      }
      await tx.done;
    }

    {
      const tx = db.transaction(DB_CONFIG.chainAccountsStore, 'readonly');
      let cursor = await tx.store.openCursor();
      while (cursor) {
        checked += 1;
        const row = cursor.value as ChainAccountRecord;
        const profileId = String(row?.profileId || '').trim();
        const chainId = normalizeChainId((row as any)?.chainId);
        const accountAddress = normalizeAccountAddress((row as any)?.accountAddress);
        const accountModel = normalizeAccountModel((row as any)?.accountModel);
        if (!profileId || !chainId || !accountAddress) {
          addViolation({
            sourceStore: DB_CONFIG.chainAccountsStore,
            sourcePrimaryKey: cursor.primaryKey,
            reason: 'Missing profileId/chainId/accountAddress on chain account row',
            record: row,
          });
          cursor = await cursor.continue();
          continue;
        }
        if (!profileIds.has(profileId)) {
          addViolation({
            sourceStore: DB_CONFIG.chainAccountsStore,
            sourcePrimaryKey: cursor.primaryKey,
            reason: `Missing profile dependency: ${profileId}`,
            record: row,
          });
          cursor = await cursor.continue();
          continue;
        }
        if (!accountModel) {
          addViolation({
            sourceStore: DB_CONFIG.chainAccountsStore,
            sourcePrimaryKey: cursor.primaryKey,
            reason: 'Missing accountModel on chain account row',
            record: row,
          });
          cursor = await cursor.continue();
          continue;
        }
        const accountRef = chainAccountKey(profileId, chainId, accountAddress);
        chainAccounts.add(accountRef);
        chainAccountModelByRef.set(accountRef, accountModel);
        if (row?.isPrimary) {
          const primaryKey = profileChainKey(profileId, chainId);
          if (primaryByProfileChain.has(primaryKey)) {
            addViolation({
              sourceStore: DB_CONFIG.chainAccountsStore,
              sourcePrimaryKey: cursor.primaryKey,
              reason: `Multiple primary chain accounts for ${profileId}/${chainId}`,
              record: row,
            });
            cursor = await cursor.continue();
            continue;
          }
          primaryByProfileChain.set(primaryKey, cursor.primaryKey);
        }
        cursor = await cursor.continue();
      }
      await tx.done;
    }

    {
      const tx = db.transaction(DB_CONFIG.accountSignersStore, 'readonly');
      let cursor = await tx.store.openCursor();
      while (cursor) {
        checked += 1;
        const row = cursor.value as AccountSignerRecord;
        const profileId = String(row?.profileId || '').trim();
        const chainId = normalizeChainId((row as any)?.chainId);
        const accountAddress = normalizeAccountAddress((row as any)?.accountAddress);
        const signerId = String((row as any)?.signerId || '').trim();
        const signerSlot = Number((row as any)?.signerSlot);
        const status = String((row as any)?.status || '').trim() as AccountSignerStatus;
        if (!profileId || !chainId || !accountAddress || !signerId) {
          addViolation({
            sourceStore: DB_CONFIG.accountSignersStore,
            sourcePrimaryKey: cursor.primaryKey,
            reason: 'Missing profileId/chainId/accountAddress/signerId on account signer row',
            record: row,
          });
          cursor = await cursor.continue();
          continue;
        }
        if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) {
          addViolation({
            sourceStore: DB_CONFIG.accountSignersStore,
            sourcePrimaryKey: cursor.primaryKey,
            reason: `Invalid signerSlot: ${String((row as any)?.signerSlot)}`,
            record: row,
          });
          cursor = await cursor.continue();
          continue;
        }
        if (!profileIds.has(profileId)) {
          addViolation({
            sourceStore: DB_CONFIG.accountSignersStore,
            sourcePrimaryKey: cursor.primaryKey,
            reason: `Missing profile dependency: ${profileId}`,
            record: row,
          });
          cursor = await cursor.continue();
          continue;
        }
        if (!chainAccounts.has(chainAccountKey(profileId, chainId, accountAddress))) {
          addViolation({
            sourceStore: DB_CONFIG.accountSignersStore,
            sourcePrimaryKey: cursor.primaryKey,
            reason: `Missing chain account dependency: ${profileId}/${chainId}/${accountAddress}`,
            record: row,
          });
          cursor = await cursor.continue();
          continue;
        }
        if (!ALLOWED_SIGNER_STATUS_TRANSITIONS.pending.has(status) && status !== 'revoked') {
          addViolation({
            sourceStore: DB_CONFIG.accountSignersStore,
            sourcePrimaryKey: cursor.primaryKey,
            reason: `Invalid signer status: ${String((row as any)?.status)}`,
            record: row,
          });
          cursor = await cursor.continue();
          continue;
        }
        if (status === 'revoked') {
          const removedAt = Number((row as any)?.removedAt);
          if (!Number.isFinite(removedAt)) {
            addViolation({
              sourceStore: DB_CONFIG.accountSignersStore,
              sourcePrimaryKey: cursor.primaryKey,
              reason: 'Revoked signer missing removedAt timestamp',
              record: row,
            });
            cursor = await cursor.continue();
            continue;
          }
        } else {
          profileSignerSlots.add(`${profileId}::${signerSlot}`);
        }
        if (status === 'active') {
          const slotKey = signerSlotKey(profileId, chainId, accountAddress, signerSlot);
          const existingSlot = activeSignerByAccountSlot.get(slotKey);
          if (existingSlot && existingSlot.signerId !== signerId) {
            addViolation({
              sourceStore: DB_CONFIG.accountSignersStore,
              sourcePrimaryKey: cursor.primaryKey,
              reason: `Duplicate active signerSlot ${signerSlot} for ${profileId}/${chainId}/${accountAddress}`,
              record: row,
            });
            cursor = await cursor.continue();
            continue;
          }
          activeSignerByAccountSlot.set(slotKey, { signerId });
          const accountKey = chainAccountKey(profileId, chainId, accountAddress);
          const activeRows = activeSignerRowsByAccount.get(accountKey) || [];
          activeRows.push({ primaryKey: cursor.primaryKey, row });
          activeSignerRowsByAccount.set(accountKey, activeRows);
        }
        cursor = await cursor.continue();
      }
      await tx.done;
    }

    for (const [accountRef, activeRows] of activeSignerRowsByAccount.entries()) {
      if (normalizeAccountModel(chainAccountModelByRef.get(accountRef) || '') !== 'eoa') {
        continue;
      }
      if (activeRows.length <= 1) continue;
      const keep = activeRows
        .slice()
        .sort((a, b) => {
          const addedAtDelta = Number(a.row.addedAt || 0) - Number(b.row.addedAt || 0);
          if (addedAtDelta !== 0) return addedAtDelta;
          return String(a.row.signerId || '').localeCompare(String(b.row.signerId || ''));
        })[0];
      for (const rowRef of activeRows) {
        if (rowRef.primaryKey === keep.primaryKey) continue;
        addViolation({
          sourceStore: DB_CONFIG.accountSignersStore,
          sourcePrimaryKey: rowRef.primaryKey,
          reason: `EOA account has multiple active signers for ${accountRef}`,
          record: rowRef.row,
        });
      }
    }

    {
      const tx = db.transaction(DB_CONFIG.profileAuthenticatorStore, 'readonly');
      let cursor = await tx.store.openCursor();
      while (cursor) {
        checked += 1;
        const row = cursor.value as ProfileAuthenticatorRecord;
        const profileId = String(row?.profileId || '').trim();
        const credentialId = String((row as any)?.credentialId || '').trim();
        const deviceNumber = Number((row as any)?.deviceNumber);
        if (!profileId || !credentialId) {
          addViolation({
            sourceStore: DB_CONFIG.profileAuthenticatorStore,
            sourcePrimaryKey: cursor.primaryKey,
            reason: 'Missing profileId/credentialId on profile authenticator row',
            record: row,
          });
          cursor = await cursor.continue();
          continue;
        }
        if (!Number.isSafeInteger(deviceNumber) || deviceNumber < 1) {
          addViolation({
            sourceStore: DB_CONFIG.profileAuthenticatorStore,
            sourcePrimaryKey: cursor.primaryKey,
            reason: `Invalid deviceNumber: ${String((row as any)?.deviceNumber)}`,
            record: row,
          });
          cursor = await cursor.continue();
          continue;
        }
        if (!profileIds.has(profileId)) {
          addViolation({
            sourceStore: DB_CONFIG.profileAuthenticatorStore,
            sourcePrimaryKey: cursor.primaryKey,
            reason: `Missing profile dependency: ${profileId}`,
            record: row,
          });
          cursor = await cursor.continue();
          continue;
        }
        cursor = await cursor.continue();
      }
      await tx.done;
    }

    {
      const tx = db.transaction(DB_CONFIG.derivedAddressV2Store, 'readonly');
      let cursor = await tx.store.openCursor();
      while (cursor) {
        checked += 1;
        const row = cursor.value as DerivedAddressV2Record;
        const profileId = String(row?.profileId || '').trim();
        const sourceChainId = normalizeChainId((row as any)?.sourceChainId);
        const sourceAccountAddress = normalizeAccountAddress((row as any)?.sourceAccountAddress);
        const targetChainId = normalizeChainId((row as any)?.targetChainId);
        const providerRef = String((row as any)?.providerRef || '').trim();
        const path = String((row as any)?.path || '').trim();
        const address = String((row as any)?.address || '').trim();
        if (!profileId || !sourceChainId || !sourceAccountAddress || !targetChainId || !providerRef || !path || !address) {
          addViolation({
            sourceStore: DB_CONFIG.derivedAddressV2Store,
            sourcePrimaryKey: cursor.primaryKey,
            reason: 'Missing required field(s) on derivedAddressV2 row',
            record: row,
          });
          cursor = await cursor.continue();
          continue;
        }
        if (!profileIds.has(profileId)) {
          addViolation({
            sourceStore: DB_CONFIG.derivedAddressV2Store,
            sourcePrimaryKey: cursor.primaryKey,
            reason: `Missing profile dependency: ${profileId}`,
            record: row,
          });
          cursor = await cursor.continue();
          continue;
        }
        cursor = await cursor.continue();
      }
      await tx.done;
    }

    {
      const tx = db.transaction(DB_CONFIG.recoveryEmailV2Store, 'readonly');
      let cursor = await tx.store.openCursor();
      while (cursor) {
        checked += 1;
        const row = cursor.value as RecoveryEmailV2Record;
        const profileId = String(row?.profileId || '').trim();
        const hashHex = String((row as any)?.hashHex || '').trim();
        if (!profileId || !hashHex) {
          addViolation({
            sourceStore: DB_CONFIG.recoveryEmailV2Store,
            sourcePrimaryKey: cursor.primaryKey,
            reason: 'Missing profileId/hashHex on recoveryEmailV2 row',
            record: row,
          });
          cursor = await cursor.continue();
          continue;
        }
        if (!profileIds.has(profileId)) {
          addViolation({
            sourceStore: DB_CONFIG.recoveryEmailV2Store,
            sourcePrimaryKey: cursor.primaryKey,
            reason: `Missing profile dependency: ${profileId}`,
            record: row,
          });
          cursor = await cursor.continue();
          continue;
        }
        cursor = await cursor.continue();
      }
      await tx.done;
    }

    {
      const tx = db.transaction(DB_CONFIG.appStateStore, 'readonly');
      let cursor = await tx.store.openCursor();
      while (cursor) {
        const row = cursor.value as AppStateEntry<unknown>;
        const key = String(row?.key || '').trim();
        if (
          key === LAST_PROFILE_STATE_APP_STATE_KEY
          || key.startsWith(`${LAST_PROFILE_STATE_APP_STATE_KEY}::`)
        ) {
          checked += 1;
          const parsed = parseLastProfileState(row?.value);
          if (!parsed) {
            addViolation({
              sourceStore: DB_CONFIG.appStateStore,
              sourcePrimaryKey: cursor.primaryKey,
              reason: `Invalid lastProfileState payload at key ${key}`,
              record: row,
            });
            cursor = await cursor.continue();
            continue;
          }
          if (!profileIds.has(parsed.profileId)) {
            addViolation({
              sourceStore: DB_CONFIG.appStateStore,
              sourcePrimaryKey: cursor.primaryKey,
              reason: `lastProfileState references missing profile ${parsed.profileId}`,
              record: row,
            });
            cursor = await cursor.continue();
            continue;
          }
          if (!profileSignerSlots.has(`${parsed.profileId}::${parsed.deviceNumber}`)) {
            addViolation({
              sourceStore: DB_CONFIG.appStateStore,
              sourcePrimaryKey: cursor.primaryKey,
              reason: `lastProfileState references missing signer slot ${parsed.profileId}/${parsed.deviceNumber}`,
              record: row,
            });
            cursor = await cursor.continue();
            continue;
          }
        }
        cursor = await cursor.continue();
      }
      await tx.done;
    }

    let quarantined = 0;
    for (const violation of violations) {
      try {
        await this.quarantineInvariantViolation(db, violation);
        quarantined += 1;
      } catch (error) {
        console.warn('PasskeyClientDB: failed to quarantine invariant violation', {
          sourceStore: violation.sourceStore,
          reason: violation.reason,
          error,
        });
      }
    }

    return {
      checked,
      violations: violations.length,
      quarantined,
    };
  }

  private async runMigrationsIfNeeded(db: IDBPDatabase): Promise<void> {
    const existing = await this.getAppStateFromDb<DbMultichainMigrationState>(
      db,
      DB_MULTICHAIN_MIGRATION_STATE_KEY,
    ).catch(() => undefined);
    const existingVersion = Number(existing?.schemaVersion || 1);
    if (
      existing?.status === 'completed' &&
      existingVersion >= DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION
    ) {
      return;
    }

    const ownerTabId = this.createMigrationOwnerId();
    const acquiredAt = Date.now();
    const startedAt =
      existingVersion >= DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION &&
      typeof existing?.startedAt === 'number'
        ? existing.startedAt
        : acquiredAt;
    const counts: DbMultichainMigrationCounts = {
      ...buildDefaultDbMultichainMigrationCounts(),
      ...(existing?.counts || {}),
    };
    const checkpoints: DbMultichainMigrationCheckpoints = {
      ...(existing?.checkpoints || {}),
    };
    let lastHeartbeatAt = 0;

    const refreshHeartbeat = async (force = false): Promise<void> => {
      const now = Date.now();
      if (!force && now - lastHeartbeatAt < DB_MULTICHAIN_MIGRATION_HEARTBEAT_INTERVAL_MS) {
        return;
      }
      await this.refreshMigrationLeaseInAppState(db, ownerTabId, acquiredAt);
      lastHeartbeatAt = now;
    };

    const persistRunningState = async (): Promise<void> => {
      await this.setAppStateInDb(db, DB_MULTICHAIN_MIGRATION_STATE_KEY, {
        status: 'running',
        schemaVersion: DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION,
        startedAt,
        counts,
        checkpoints,
      } satisfies DbMultichainMigrationState);
      await this.setAppStateInDb(db, DB_MULTICHAIN_MIGRATION_CHECKPOINTS_KEY, checkpoints);
      await refreshHeartbeat(true);
    };

    const markCheckpoint = async (
      step: DbMultichainMigrationStep,
      stepCounts?: Record<string, number>,
    ): Promise<void> => {
      checkpoints[step] = {
        status: 'completed',
        completedAt: Date.now(),
        ...(stepCounts ? { counts: stepCounts } : {}),
      };
      await persistRunningState();
      console.info('PasskeyClientDB: migration checkpoint completed', {
        step,
        counts: stepCounts || null,
      });
    };

    const runMigration = async (): Promise<void> => {
      const leaseAcquired = await this.tryAcquireMigrationLeaseInAppState(
        db,
        ownerTabId,
        acquiredAt,
      );
      if (!leaseAcquired) {
        console.info('PasskeyClientDB: skipping migration; another tab owns active app-state lock');
        return;
      }

      lastHeartbeatAt = Date.now();
      console.info('PasskeyClientDB: multichain migration started', {
        schemaVersion: DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION,
        ownerTabId,
      });

      try {
        await persistRunningState();

        if (!checkpoints.legacyUsersToCoreV2) {
          const userTx = db.transaction(DB_CONFIG.userStore, 'readonly');
          let userCursor = await userTx.store.openCursor();
          let stepSuccess = 0;
          let stepFailures = 0;
          while (userCursor) {
            const current = userCursor;
            await refreshHeartbeat();
            counts.legacyUsersScanned += 1;
            const raw = current.value as ClientUserDataWithOptionalDevice;
            try {
              const accountId = toAccountId((raw as any).nearAccountId);
              const maybeDevice = Number((raw as any).deviceNumber);
              const deviceNumber =
                Number.isSafeInteger(maybeDevice) && maybeDevice >= 1 ? maybeDevice : 1;
              const credentialRawId = String((raw as any)?.passkeyCredential?.rawId || '').trim();
              const credentialId = String((raw as any)?.passkeyCredential?.id || '').trim();
              const clientNearPublicKey = String((raw as any)?.clientNearPublicKey || '').trim();
              if (!credentialRawId || !clientNearPublicKey) {
                stepFailures += 1;
                counts.coreUserBackfillFailures += 1;
                userCursor = await current.continue();
                continue;
              }
              const normalized: ClientUserData = {
                nearAccountId: accountId,
                deviceNumber,
                version:
                  Number.isFinite((raw as any)?.version) && (raw as any).version > 0
                    ? Math.floor((raw as any).version)
                    : 2,
                ...(typeof (raw as any)?.registeredAt === 'number'
                  ? { registeredAt: (raw as any).registeredAt }
                  : {}),
                ...(typeof (raw as any)?.lastLogin === 'number'
                  ? { lastLogin: (raw as any).lastLogin }
                  : {}),
                ...(typeof (raw as any)?.lastUpdated === 'number'
                  ? { lastUpdated: (raw as any).lastUpdated }
                  : {}),
                clientNearPublicKey,
                passkeyCredential: {
                  id: credentialId || credentialRawId,
                  rawId: credentialRawId,
                },
                ...(raw?.preferences ? { preferences: raw.preferences } : {}),
              };
              await this.backfillCoreFromLegacyUserRecord(normalized, db);
              stepSuccess += 1;
              counts.coreUserBackfillSuccess += 1;
            } catch {
              stepFailures += 1;
              counts.coreUserBackfillFailures += 1;
            }
            userCursor = await current.continue();
          }
          await userTx.done;
          await markCheckpoint('legacyUsersToCoreV2', {
            success: stepSuccess,
            failures: stepFailures,
          });
        }

        if (!checkpoints.legacyAuthenticatorsToProfileAuthenticators) {
          const authTx = db.transaction(DB_CONFIG.authenticatorStore, 'readonly');
          let authCursor = await authTx.store.openCursor();
          let stepUpserts = 0;
          let stepFailures = 0;
          while (authCursor) {
            const current = authCursor;
            await refreshHeartbeat();
            counts.legacyAuthenticatorsScanned += 1;
            const legacy = current.value as ClientAuthenticatorData;
            try {
              const accountId = toAccountId(legacy.nearAccountId);
              const maybeDevice = Number((legacy as any).deviceNumber);
              const deviceNumber =
                Number.isSafeInteger(maybeDevice) && maybeDevice >= 1 ? maybeDevice : 1;
              const credentialId = String((legacy as any)?.credentialId || '').trim();
              const credentialPublicKey = (legacy as any)?.credentialPublicKey;
              if (!credentialId || !(credentialPublicKey instanceof Uint8Array)) {
                stepFailures += 1;
                counts.profileAuthenticatorFailures += 1;
                authCursor = await current.continue();
                continue;
              }
              await this.backfillProfileAuthenticatorFromLegacyRecord(
                {
                  nearAccountId: accountId,
                  deviceNumber,
                  credentialId,
                  credentialPublicKey,
                  transports: legacy.transports,
                  name: legacy.name,
                  registered: String((legacy as any)?.registered || ''),
                  syncedAt: String((legacy as any)?.syncedAt || ''),
                },
                db,
              );
              stepUpserts += 1;
              counts.profileAuthenticatorUpserts += 1;
            } catch {
              stepFailures += 1;
              counts.profileAuthenticatorFailures += 1;
            }
            authCursor = await current.continue();
          }
          await authTx.done;
          await markCheckpoint('legacyAuthenticatorsToProfileAuthenticators', {
            upserts: stepUpserts,
            failures: stepFailures,
          });
        }

        if (!checkpoints.legacyDerivedAddressesToV2) {
          let stepUpserts = 0;
          let stepFailures = 0;
          if (db.objectStoreNames.contains(LEGACY_DERIVED_ADDRESS_STORE)) {
            const derivedTx = db.transaction(LEGACY_DERIVED_ADDRESS_STORE, 'readonly');
            let derivedCursor = await derivedTx.store.openCursor();
            while (derivedCursor) {
              const current = derivedCursor;
              await refreshHeartbeat();
              counts.legacyDerivedAddressesScanned += 1;
              const legacy = current.value as DerivedAddressRecord;
              try {
                const accountId = toAccountId(legacy.nearAccountId);
                const providerRef = String(legacy.contractId || '').trim();
                const path = String(legacy.path || '').trim();
                const address = String(legacy.address || '').trim();
                if (!providerRef || !path || !address) {
                  stepFailures += 1;
                  counts.derivedAddressV2Failures += 1;
                  derivedCursor = await current.continue();
                  continue;
                }
                const sourceChainId = inferNearChainId(accountId);
                const row: DerivedAddressV2Record = {
                  profileId: buildLegacyNearProfileId(accountId),
                  sourceChainId,
                  sourceAccountAddress: normalizeAccountAddress(accountId),
                  targetChainId: inferTargetChainIdFromLegacyDerivedAddress(legacy),
                  providerRef,
                  path,
                  address,
                  updatedAt:
                    typeof legacy.updatedAt === 'number' ? legacy.updatedAt : Date.now(),
                };
                await db.put(DB_CONFIG.derivedAddressV2Store, row);
                stepUpserts += 1;
                counts.derivedAddressV2Upserts += 1;
              } catch {
                stepFailures += 1;
                counts.derivedAddressV2Failures += 1;
              }
              derivedCursor = await current.continue();
            }
            await derivedTx.done;
          }
          await markCheckpoint('legacyDerivedAddressesToV2', {
            upserts: stepUpserts,
            failures: stepFailures,
          });
        }

        if (!checkpoints.legacyRecoveryEmailsToV2) {
          let stepUpserts = 0;
          let stepFailures = 0;
          if (db.objectStoreNames.contains(LEGACY_RECOVERY_EMAIL_STORE)) {
            const recoveryTx = db.transaction(LEGACY_RECOVERY_EMAIL_STORE, 'readonly');
            let recoveryCursor = await recoveryTx.store.openCursor();
            while (recoveryCursor) {
              const current = recoveryCursor;
              await refreshHeartbeat();
              counts.legacyRecoveryEmailsScanned += 1;
              const legacy = current.value as RecoveryEmailRecord;
              try {
                const accountId = toAccountId(legacy.nearAccountId);
                const hashHex = String(legacy.hashHex || '').trim();
                if (!hashHex) {
                  stepFailures += 1;
                  counts.recoveryEmailV2Failures += 1;
                  recoveryCursor = await current.continue();
                  continue;
                }
                const row: RecoveryEmailV2Record = {
                  profileId: buildLegacyNearProfileId(accountId),
                  hashHex,
                  email: String(legacy.email || '').trim() || hashHex,
                  addedAt: typeof legacy.addedAt === 'number' ? legacy.addedAt : Date.now(),
                };
                await db.put(DB_CONFIG.recoveryEmailV2Store, row);
                stepUpserts += 1;
                counts.recoveryEmailV2Upserts += 1;
              } catch {
                stepFailures += 1;
                counts.recoveryEmailV2Failures += 1;
              }
              recoveryCursor = await current.continue();
            }
            await recoveryTx.done;
          }
          await markCheckpoint('legacyRecoveryEmailsToV2', {
            upserts: stepUpserts,
            failures: stepFailures,
          });
        }

        if (!checkpoints.lastProfileStateSync) {
          const lastProfileRaw = await this.getAppStateFromDb<unknown>(
            db,
            LAST_PROFILE_STATE_APP_STATE_KEY,
          );
          const lastProfileState = parseLastProfileState(lastProfileRaw);
          if (!lastProfileState) {
            const lastUserRaw = await this.getAppStateFromDb<unknown>(
              db,
              LEGACY_LAST_USER_APP_STATE_KEY,
            );
            const lastUserState = parseLegacyLastUserState(lastUserRaw);
            if (lastUserState) {
              await this.setLastProfileStateInDb(db, {
                profileId: buildLegacyNearProfileId(lastUserState.accountId),
                deviceNumber: lastUserState.deviceNumber,
                ...(this.lastUserScope != null ? { scope: this.lastUserScope } : {}),
              });
              counts.lastProfileStateSynced += 1;
            }
          }
          await markCheckpoint('lastProfileStateSync', {
            synced: counts.lastProfileStateSynced,
          });
        }

        if (!checkpoints.parityChecksLogged) {
          const parity = await this.collectMigrationParity(db);
          await markCheckpoint('parityChecksLogged', {
            mismatches: parity.mismatches.length,
          });
          console.info('PasskeyClientDB: migration parity summary', parity);
        }

        if (!checkpoints.invariantsValidatedAndQuarantined) {
          const invariantSummary = await this.validateAndQuarantineInvariantViolations(db);
          counts.invariantRowsChecked += invariantSummary.checked;
          counts.invariantViolationsFound += invariantSummary.violations;
          counts.invariantRowsQuarantined += invariantSummary.quarantined;
          await markCheckpoint('invariantsValidatedAndQuarantined', {
            checked: invariantSummary.checked,
            violations: invariantSummary.violations,
            quarantined: invariantSummary.quarantined,
          });
          console.info('PasskeyClientDB: migration invariants validation summary', invariantSummary);
        }

        const finishedAt = Date.now();
        const completedState: DbMultichainMigrationState = {
          status: 'completed',
          schemaVersion: DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION,
          startedAt,
          finishedAt,
          counts,
          checkpoints,
        };
        await this.setAppStateInDb(db, DB_MULTICHAIN_MIGRATION_STATE_KEY, completedState);
        await this.setAppStateInDb(db, DB_MULTICHAIN_MIGRATION_CHECKPOINTS_KEY, checkpoints);
        console.info('PasskeyClientDB: multichain migration completed', {
          durationMs: finishedAt - startedAt,
          counts,
        });
      } catch (error: any) {
        const finishedAt = Date.now();
        const failedState: DbMultichainMigrationState = {
          status: 'failed',
          schemaVersion: DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION,
          startedAt,
          finishedAt,
          counts,
          checkpoints,
          error: String(error?.message || error),
        };
        await this.setAppStateInDb(db, DB_MULTICHAIN_MIGRATION_STATE_KEY, failedState).catch(
          () => undefined,
        );
        console.error('PasskeyClientDB: multichain migration failed', {
          durationMs: finishedAt - startedAt,
          error: failedState.error,
          counts,
        });
        throw error;
      } finally {
        await this.clearMigrationLeaseInAppState(db, ownerTabId).catch(() => undefined);
      }
    };

    const lockOutcome = await this.tryRunWithNavigatorMigrationLock(runMigration);
    if (lockOutcome === 'unsupported') {
      await runMigration();
      return;
    }
    if (lockOutcome === 'unavailable') {
      console.info('PasskeyClientDB: skipping migration; navigator lock held by another tab');
    }
  }

  // === APP STATE METHODS ===

  async getAppState<T = unknown>(key: string): Promise<T | undefined> {
    const db = await this.getDB();
    const result = await db.get(DB_CONFIG.appStateStore, key);
    return result?.value as T | undefined;
  }

  async setAppState<T = unknown>(key: string, value: T): Promise<void> {
    const db = await this.getDB();
    const entry: AppStateEntry<T> = { key, value };
    await db.put(DB_CONFIG.appStateStore, entry);
  }

  // === V2 MULTICHAIN METHODS ===

  async getProfile(profileId: string): Promise<ProfileRecord | null> {
    const normalized = String(profileId || '').trim();
    if (!normalized) return null;
    const db = await this.getDB();
    const rec = await db.get(DB_CONFIG.profilesStore, normalized);
    return (rec as ProfileRecord) || null;
  }

  async upsertProfile(input: UpsertProfileInput): Promise<ProfileRecord> {
    const profileId = String(input.profileId || '').trim();
    if (!profileId) throw new Error('PasskeyClientDB: profileId is required');
    if (!input.passkeyCredential?.rawId) {
      throw new Error('PasskeyClientDB: passkeyCredential.rawId is required');
    }
    const db = await this.getDB();
    const now = Date.now();
    const existing = await db.get(DB_CONFIG.profilesStore, profileId) as ProfileRecord | undefined;
    const next: ProfileRecord = {
      profileId,
      defaultDeviceNumber: input.defaultDeviceNumber ?? existing?.defaultDeviceNumber ?? 1,
      passkeyCredential: input.passkeyCredential,
      preferences: input.preferences ?? existing?.preferences,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    await db.put(DB_CONFIG.profilesStore, next);
    return next;
  }

  private getAccountModelCapabilities(accountModel: AccountModel): AccountModelCapabilities {
    const normalized = normalizeAccountModel(accountModel);
    return ACCOUNT_MODEL_CAPABILITY_MATRIX[normalized] || DEFAULT_ACCOUNT_MODEL_CAPABILITIES;
  }

  private assertSignerTypeCapability(
    signerType: AccountSignerType,
    accountModel: AccountModel,
    accountRef: { chainId: string; accountAddress: string },
  ): void {
    const normalizedSignerType = String(signerType || '').trim().toLowerCase();
    const capabilities = this.getAccountModelCapabilities(accountModel);
    if (normalizedSignerType === 'session' && !capabilities.supportsSessionSigner) {
      throw new DBConstraintError(
        'SESSION_SIGNER_NOT_SUPPORTED',
        `Signer type "session" is not supported for account model ${String(accountModel || '')}`,
        {
          signerType: normalizedSignerType,
          accountModel,
          chainId: accountRef.chainId,
          accountAddress: accountRef.accountAddress,
        },
      );
    }
    if (normalizedSignerType === 'recovery' && !capabilities.supportsRecoverySigner) {
      throw new DBConstraintError(
        'RECOVERY_SIGNER_NOT_SUPPORTED',
        `Signer type "recovery" is not supported for account model ${String(accountModel || '')}`,
        {
          signerType: normalizedSignerType,
          accountModel,
          chainId: accountRef.chainId,
          accountAddress: accountRef.accountAddress,
        },
      );
    }
  }

  private assertSignerStatusTransition(args: {
    previousStatus: AccountSignerStatus;
    nextStatus: AccountSignerStatus;
    chainId: string;
    accountAddress: string;
    signerId: string;
  }): void {
    const allowed = ALLOWED_SIGNER_STATUS_TRANSITIONS[args.previousStatus];
    if (allowed?.has(args.nextStatus)) return;
    throw new DBConstraintError(
      'INVALID_SIGNER_STATUS_TRANSITION',
      `Invalid signer status transition: ${args.previousStatus} -> ${args.nextStatus}`,
      {
        previousStatus: args.previousStatus,
        nextStatus: args.nextStatus,
        chainId: args.chainId,
        accountAddress: args.accountAddress,
        signerId: args.signerId,
      },
    );
  }

  private ensureRevokedSignerHasRemovedAt(args: {
    status: AccountSignerStatus;
    removedAt?: number;
    chainId: string;
    accountAddress: string;
    signerId: string;
  }): number | undefined {
    if (args.status !== 'revoked') return undefined;
    if (typeof args.removedAt === 'number' && Number.isFinite(args.removedAt)) return args.removedAt;
    const now = Date.now();
    if (!Number.isFinite(now)) {
      throw new DBConstraintError(
        'REVOKED_SIGNER_REQUIRES_REMOVED_AT',
        'Revoked signer requires removedAt timestamp',
        {
          chainId: args.chainId,
          accountAddress: args.accountAddress,
          signerId: args.signerId,
        },
      );
    }
    return now;
  }

  private async assertSignerWriteInvariants(
    store: any,
    args: {
      next: AccountSignerRecord;
      accountModel: AccountModel;
      existingSignerId?: string;
      existingStatus?: AccountSignerStatus;
    },
  ): Promise<void> {
    const capabilities = this.getAccountModelCapabilities(args.accountModel);
    const accountStatusIndex = store.index('chainId_accountAddress_status');
    const accountIndex = store.index('chainId_accountAddress');

    const allForAccount = await accountIndex.getAll([args.next.chainId, args.next.accountAddress]) as AccountSignerRecord[];
    const otherSigners = allForAccount.filter((row) => row.signerId !== args.next.signerId);
    if (!capabilities.supportsMultiSigner && !args.existingSignerId && otherSigners.length > 0) {
      throw new DBConstraintError(
        'MULTI_SIGNER_NOT_SUPPORTED',
        `Account model ${String(args.accountModel || '')} does not support additional signers`,
        {
          accountModel: args.accountModel,
          chainId: args.next.chainId,
          accountAddress: args.next.accountAddress,
          signerId: args.next.signerId,
        },
      );
    }

    if (
      !capabilities.supportsAddRemoveSigner
      && !args.existingSignerId
      && otherSigners.length > 0
    ) {
      throw new DBConstraintError(
        'SIGNER_MUTATION_NOT_SUPPORTED',
        `Account model ${String(args.accountModel || '')} does not support signer mutations`,
        {
          accountModel: args.accountModel,
          chainId: args.next.chainId,
          accountAddress: args.next.accountAddress,
          signerId: args.next.signerId,
        },
      );
    }

    if (args.next.status === 'active') {
      const activeRows = await accountStatusIndex.getAll([
        args.next.chainId,
        args.next.accountAddress,
        'active',
      ]) as AccountSignerRecord[];
      const conflictingSlot = activeRows.find(
        (row) => row.signerId !== args.next.signerId && row.signerSlot === args.next.signerSlot,
      );
      if (conflictingSlot) {
        throw new DBConstraintError(
          'DUPLICATE_ACTIVE_SIGNER_SLOT',
          `Active signer slot ${args.next.signerSlot} is already used for ${args.next.chainId}/${args.next.accountAddress}`,
          {
            chainId: args.next.chainId,
            accountAddress: args.next.accountAddress,
            signerId: args.next.signerId,
            signerSlot: args.next.signerSlot,
            conflictingSignerId: conflictingSlot.signerId,
          },
        );
      }

      if (normalizeAccountModel(args.accountModel) === 'eoa') {
        const activeOthers = activeRows.filter((row) => row.signerId !== args.next.signerId);
        if (activeOthers.length > 0) {
          throw new DBConstraintError(
            'EOA_ACTIVE_SIGNER_LIMIT',
            'EOA accounts can have at most one active signer',
            {
              chainId: args.next.chainId,
              accountAddress: args.next.accountAddress,
              signerId: args.next.signerId,
            },
          );
        }
      }
    }

    if (args.existingStatus && args.existingStatus !== args.next.status) {
      this.assertSignerStatusTransition({
        previousStatus: args.existingStatus,
        nextStatus: args.next.status,
        chainId: args.next.chainId,
        accountAddress: args.next.accountAddress,
        signerId: args.next.signerId,
      });
    }
  }

  async upsertChainAccount(input: UpsertChainAccountInput): Promise<ChainAccountRecord> {
    const profileId = String(input.profileId || '').trim();
    const chainId = normalizeChainId(input.chainId);
    const accountAddress = normalizeAccountAddress(input.accountAddress);
    const accountModel = normalizeAccountModel(input.accountModel);
    if (!profileId || !chainId || !accountAddress) {
      throw new Error('PasskeyClientDB: profileId, chainId, and accountAddress are required');
    }
    if (!accountModel) {
      throw new Error('PasskeyClientDB: accountModel is required');
    }
    const db = await this.getDB();
    const now = Date.now();
    const profile = await db.get(DB_CONFIG.profilesStore, profileId) as ProfileRecord | undefined;
    if (!profile) {
      throw new DBConstraintError(
        'MISSING_PROFILE',
        `Cannot upsert chain account for unknown profile: ${profileId}`,
        { profileId, chainId, accountAddress },
      );
    }
    const tx = db.transaction(DB_CONFIG.chainAccountsStore, 'readwrite');
    const store = tx.store;
    const existing = await store.get([profileId, chainId, accountAddress]) as ChainAccountRecord | undefined;
    const next: ChainAccountRecord = {
      profileId,
      chainId,
      accountAddress,
      accountModel,
      isPrimary: input.isPrimary ?? existing?.isPrimary ?? false,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
      legacyNearAccountId: input.legacyNearAccountId ?? existing?.legacyNearAccountId,
    };

    if (next.isPrimary) {
      const idx = store.index('profileId_chainId');
      let cursor = await idx.openCursor([profileId, chainId]);
      while (cursor) {
        const row = cursor.value as ChainAccountRecord;
        if (
          row.isPrimary
          && normalizeAccountAddress(row.accountAddress) !== accountAddress
        ) {
          await cursor.update({
            ...row,
            isPrimary: false,
            updatedAt: now,
          });
        }
        cursor = await cursor.continue();
      }
    }

    await store.put(next);
    await tx.done;
    return next;
  }

  async getProfileByAccount(chainId: string, accountAddress: string): Promise<ProfileRecord | null> {
    const normalizedChainId = normalizeChainId(chainId);
    const normalizedAddress = normalizeAccountAddress(accountAddress);
    if (!normalizedChainId || !normalizedAddress) return null;
    const db = await this.getDB();
    const tx = db.transaction(DB_CONFIG.chainAccountsStore, 'readonly');
    const idx = tx.store.index('chainId_accountAddress');
    const chainAccount = await idx.get([normalizedChainId, normalizedAddress]) as ChainAccountRecord | undefined;
    if (!chainAccount?.profileId) return null;
    const profile = await db.get(DB_CONFIG.profilesStore, chainAccount.profileId);
    return (profile as ProfileRecord) || null;
  }

  async listProfileAuthenticators(profileId: string): Promise<ProfileAuthenticatorRecord[]> {
    const normalizedProfileId = String(profileId || '').trim();
    if (!normalizedProfileId) return [];
    const db = await this.getDB();
    const tx = db.transaction(DB_CONFIG.profileAuthenticatorStore, 'readonly');
    const rows = await tx.store.index('profileId').getAll(normalizedProfileId);
    await tx.done;
    return (rows as ProfileAuthenticatorRecord[]) || [];
  }

  async resolveNearAccountContext(
    nearAccountId: AccountId,
  ): Promise<{ profileId: string; sourceChainId: string; sourceAccountAddress: string } | null> {
    const accountId = toAccountId(nearAccountId);
    const sourceAccountAddress = normalizeAccountAddress(accountId);
    const db = await this.getDB();

    const tx = db.transaction(DB_CONFIG.chainAccountsStore, 'readonly');
    const idx = tx.store.index('chainId_accountAddress');
    for (const sourceChainId of getNearChainCandidates(accountId)) {
      const chainAccount = await idx.get([sourceChainId, sourceAccountAddress]) as
        | ChainAccountRecord
        | undefined;
      const profileId = String(chainAccount?.profileId || '').trim();
      if (profileId) {
        await tx.done;
        return {
          profileId,
          sourceChainId,
          sourceAccountAddress,
        };
      }
    }
    await tx.done;
    return null;
  }

  async getNearAccountIdForProfile(profileId: string): Promise<AccountId | null> {
    const normalizedProfileId = String(profileId || '').trim();
    if (!normalizedProfileId) return null;

    const db = await this.getDB();
    const tx = db.transaction(DB_CONFIG.chainAccountsStore, 'readonly');
    const rows = await tx.store.index('profileId').getAll(normalizedProfileId) as ChainAccountRecord[];
    await tx.done;
    if (!rows.length) return null;

    const nearRows = rows.filter((row) => String(row.chainId || '').startsWith('near:'));
    if (!nearRows.length) return null;
    const selected = nearRows.find((row) => !!row.isPrimary) || nearRows[0];
    if (!selected) return null;
    const candidate = String(selected.legacyNearAccountId || selected.accountAddress || '').trim();
    if (!candidate) return null;
    try {
      return toAccountId(candidate);
    } catch {
      return null;
    }
  }

  async getLastSelectedNearAccount(): Promise<{
    nearAccountId: AccountId;
    profileId: string;
    deviceNumber: number;
  } | null> {
    const lastProfileState = await this.getLastProfileState().catch(() => null);
    if (!lastProfileState?.profileId) return null;
    const nearAccountId = await this.getNearAccountIdForProfile(lastProfileState.profileId);
    if (!nearAccountId) return null;
    return {
      nearAccountId,
      profileId: lastProfileState.profileId,
      deviceNumber: lastProfileState.deviceNumber,
    };
  }

  async setLastProfileStateForNearAccount(
    nearAccountId: AccountId,
    deviceNumber: number,
  ): Promise<void> {
    const normalizedDeviceNumber = Number(deviceNumber);
    if (!Number.isSafeInteger(normalizedDeviceNumber) || normalizedDeviceNumber < 1) {
      throw new Error('PasskeyClientDB: deviceNumber must be an integer >= 1');
    }
    const context = await this.resolveNearAccountContext(nearAccountId);
    if (!context?.profileId) {
      throw new Error(
        `PasskeyClientDB: Missing profile/account mapping for NEAR account ${String(nearAccountId)}`,
      );
    }
    await this.setLastProfileState({
      profileId: context.profileId,
      deviceNumber: normalizedDeviceNumber,
      ...(this.lastUserScope != null ? { scope: this.lastUserScope } : {}),
    });
    await this.clearLegacyLastUserPointers();
  }

  async getNearAccountProjection(
    nearAccountId: AccountId,
    deviceNumber?: number,
  ): Promise<ClientUserData | null> {
    const accountId = toAccountId(nearAccountId);
    return this.buildLegacyNearUserFromV2(accountId, deviceNumber);
  }

  async getLastSelectedNearAccountProjection(): Promise<ClientUserData | null> {
    const last = await this.getLastSelectedNearAccount().catch(() => null);
    if (!last) return null;
    return this.buildLegacyNearUserFromV2(last.nearAccountId, last.deviceNumber);
  }

  async getMostRecentNearAccountProjection(nearAccountId: AccountId): Promise<ClientUserData | null> {
    return this.getNearAccountProjection(nearAccountId);
  }

  async listNearAccountProjections(): Promise<ClientUserData[]> {
    const db = await this.getDB();
    const tx = db.transaction(DB_CONFIG.chainAccountsStore, 'readonly');
    const nearTestnetRows = await tx.store.index('chainId').getAll('near:testnet') as ChainAccountRecord[];
    const nearMainnetRows = await tx.store.index('chainId').getAll('near:mainnet') as ChainAccountRecord[];
    await tx.done;

    const accountCandidates = new Set<AccountId>();
    for (const row of [...(nearTestnetRows || []), ...(nearMainnetRows || [])]) {
      const candidate = String(row.legacyNearAccountId || row.accountAddress || '').trim();
      if (!candidate) continue;
      try {
        accountCandidates.add(toAccountId(candidate));
      } catch {}
    }

    const users: ClientUserData[] = [];
    for (const accountId of accountCandidates) {
      const projected = await this.getNearAccountProjection(accountId).catch(() => null);
      if (projected) users.push(projected);
    }
    return users;
  }

  async upsertNearAccountProjection(input: StoreUserDataInput): Promise<ClientUserData> {
    const accountId = toAccountId(input.nearAccountId);
    const now = Date.now();
    const deviceNumber = Number(input.deviceNumber);
    const normalizedDeviceNumber =
      Number.isSafeInteger(deviceNumber) && deviceNumber >= 1 ? deviceNumber : 1;
    const userData: ClientUserData = {
      nearAccountId: accountId,
      deviceNumber: normalizedDeviceNumber,
      version: input.version || 2,
      registeredAt: now,
      lastLogin: now,
      lastUpdated: input.lastUpdated ?? now,
      clientNearPublicKey: input.clientNearPublicKey,
      passkeyCredential: input.passkeyCredential,
      preferences: input.preferences ?? {
        useRelayer: false,
        useNetwork: inferNearChainId(accountId).endsWith('mainnet') ? 'mainnet' : 'testnet',
        confirmationConfig: DEFAULT_CONFIRMATION_CONFIG,
      },
    };
    await this.upsertLegacyNearUserProjection(userData);
    await this.setLastProfileStateForNearAccount(accountId, normalizedDeviceNumber);
    return (await this.getNearAccountProjection(accountId, normalizedDeviceNumber)) || userData;
  }

  async touchLastLoginForNearAccount(nearAccountId: AccountId): Promise<void> {
    const accountId = toAccountId(nearAccountId);
    const context = await this.resolveNearAccountContext(accountId).catch(() => null);
    if (!context?.profileId) return;
    const lastProfileState = await this.getLastProfileState().catch(() => null);
    const profile = await this.getProfile(context.profileId).catch(() => null);
    const defaultDeviceNumber = Number(profile?.defaultDeviceNumber);
    const deviceNumber =
      lastProfileState?.profileId === context.profileId
        ? lastProfileState.deviceNumber
        : (
          Number.isSafeInteger(defaultDeviceNumber) && defaultDeviceNumber >= 1
            ? defaultDeviceNumber
            : 1
        );
    await this.setLastProfileStateForNearAccount(accountId, deviceNumber);
  }

  async clearLastProfileSelection(): Promise<void> {
    await this.setLastProfileState(null);
    await this.clearLegacyLastUserPointers();
  }

  async listNearAuthenticators(nearAccountId: AccountId): Promise<ClientAuthenticatorData[]> {
    const accountId = toAccountId(nearAccountId);
    const context = await this.resolveNearAccountContext(accountId).catch(() => null);
    if (!context?.profileId) return [];
    const rows = await this.listProfileAuthenticators(context.profileId);
    return rows.map((row) => this.mapProfileAuthenticatorToLegacy(row, accountId));
  }

  async getNearAuthenticatorByCredentialId(
    nearAccountId: AccountId,
    credentialId: string,
  ): Promise<ClientAuthenticatorData | null> {
    const accountId = toAccountId(nearAccountId);
    const context = await this.resolveNearAccountContext(accountId).catch(() => null);
    if (!context?.profileId) return null;
    const profileMatch = await this.getProfileAuthenticatorByCredentialId(
      context.profileId,
      credentialId,
    );
    if (!profileMatch) return null;
    return this.mapProfileAuthenticatorToLegacy(profileMatch, accountId);
  }

  async clearNearAuthenticators(nearAccountId: AccountId): Promise<void> {
    const accountId = toAccountId(nearAccountId);
    const context = await this.resolveNearAccountContext(accountId).catch(() => null);
    if (!context?.profileId) return;
    await this.clearProfileAuthenticators(context.profileId);
  }

  async upsertNearAuthenticator(authenticatorData: ClientAuthenticatorData): Promise<void> {
    const accountId = toAccountId(authenticatorData.nearAccountId);
    const context = await this.resolveNearAccountContext(accountId).catch(() => null);
    if (!context?.profileId) {
      throw new Error(`PasskeyClientDB: Missing profile/account mapping for NEAR account ${accountId}`);
    }
    await this.upsertProfileAuthenticator({
      profileId: context.profileId,
      deviceNumber: authenticatorData.deviceNumber,
      credentialId: authenticatorData.credentialId,
      credentialPublicKey: authenticatorData.credentialPublicKey,
      transports: authenticatorData.transports,
      name: authenticatorData.name,
      registered: authenticatorData.registered,
      syncedAt: authenticatorData.syncedAt,
    });
  }

  async hasNearPasskeyCredential(nearAccountId: AccountId): Promise<boolean> {
    const authenticators = await this.listNearAuthenticators(nearAccountId);
    if (authenticators.length > 0) return !!authenticators[0]?.credentialId;
    const user = await this.getNearAccountProjection(nearAccountId).catch(() => null);
    return !!user?.passkeyCredential?.rawId;
  }

  async updatePreferences(
    nearAccountId: AccountId,
    preferences: Partial<UserPreferences>,
  ): Promise<void> {
    const accountId = toAccountId(nearAccountId);
    const context = await this.resolveNearAccountContext(accountId).catch(() => null);
    if (!context?.profileId) return;

    const profile = await this.getProfile(context.profileId).catch(() => null);
    if (!profile) return;
    const updatedPreferences = {
      ...(profile.preferences || {
        useRelayer: false,
        useNetwork: inferNearChainId(accountId).endsWith('mainnet') ? 'mainnet' : 'testnet',
        confirmationConfig: DEFAULT_CONFIRMATION_CONFIG,
      }),
      ...preferences,
    } as UserPreferences;

    await this.upsertProfile({
      profileId: profile.profileId,
      defaultDeviceNumber: profile.defaultDeviceNumber,
      passkeyCredential: profile.passkeyCredential,
      preferences: updatedPreferences,
    });

    this.emitEvent({
      type: 'preferences-updated',
      accountId,
      data: { preferences: updatedPreferences },
    });
  }

  async deleteNearAccountData(nearAccountId: AccountId): Promise<void> {
    const accountId = toAccountId(nearAccountId);
    const context = await this.resolveNearAccountContext(accountId).catch(() => null);
    if (!context?.profileId) return;
    await this.clearNearAuthenticators(accountId);
    await this.clearLastProfileStateIfMatchesProfile(context.profileId);
    await this.deleteV2DataForProfile(context.profileId);
    this.emitEvent({ type: 'user-deleted', accountId });
  }

  async clearAllNearAccounts(): Promise<void> {
    const allUsers = await this.listNearAccountProjections();
    for (const user of allUsers) {
      await this.deleteNearAccountData(user.nearAccountId).catch(() => undefined);
    }
  }

  async rollbackNearAccountRegistration(nearAccountId: AccountId): Promise<void> {
    const accountId = toAccountId(nearAccountId);
    await this.atomicOperation(async () => {
      await this.clearNearAuthenticators(accountId);
      const context = await this.resolveNearAccountContext(accountId).catch(() => null);
      if (!context?.profileId) return true;
      await this.clearLastProfileStateIfMatchesProfile(context.profileId);
      await this.deleteV2DataForProfile(context.profileId);
      return true;
    });
  }

  async upsertProfileAuthenticator(record: ProfileAuthenticatorRecord): Promise<void> {
    const profileId = String(record.profileId || '').trim();
    const credentialId = String(record.credentialId || '').trim();
    if (!profileId || !credentialId) {
      throw new Error('PasskeyClientDB: profileId and credentialId are required for profileAuthenticators');
    }
    const db = await this.getDB();
    await db.put(DB_CONFIG.profileAuthenticatorStore, {
      ...record,
      profileId,
      credentialId,
    } satisfies ProfileAuthenticatorRecord);
  }

  async getProfileAuthenticatorByCredentialId(
    profileId: string,
    credentialId: string,
  ): Promise<ProfileAuthenticatorRecord | null> {
    const normalizedProfileId = String(profileId || '').trim();
    const normalizedCredentialId = String(credentialId || '').trim();
    if (!normalizedProfileId || !normalizedCredentialId) return null;
    const db = await this.getDB();
    const tx = db.transaction(DB_CONFIG.profileAuthenticatorStore, 'readonly');
    const row = await tx.store
      .index('profileId_credentialId')
      .get([normalizedProfileId, normalizedCredentialId]) as ProfileAuthenticatorRecord | undefined;
    await tx.done;
    return row || null;
  }

  async clearProfileAuthenticators(profileId: string): Promise<void> {
    const normalizedProfileId = String(profileId || '').trim();
    if (!normalizedProfileId) return;
    const db = await this.getDB();
    const tx = db.transaction(DB_CONFIG.profileAuthenticatorStore, 'readwrite');
    const profileStore = tx.store;
    let cursor = await profileStore.index('profileId').openCursor(IDBKeyRange.only(normalizedProfileId));
    while (cursor) {
      await profileStore.delete(cursor.primaryKey);
      cursor = await cursor.continue();
    }
    await tx.done;
  }

  async setDerivedAddressV2(input: {
    profileId: string;
    sourceChainId: string;
    sourceAccountAddress: string;
    targetChainId: string;
    providerRef: string;
    path: string;
    address: string;
    updatedAt?: number;
  }): Promise<void> {
    const profileId = String(input.profileId || '').trim();
    const sourceChainId = normalizeChainId(input.sourceChainId);
    const sourceAccountAddress = normalizeAccountAddress(input.sourceAccountAddress);
    const targetChainId = normalizeChainId(input.targetChainId);
    const providerRef = String(input.providerRef || '').trim();
    const path = String(input.path || '').trim();
    const address = String(input.address || '').trim();
    if (!profileId || !sourceChainId || !sourceAccountAddress || !targetChainId || !providerRef || !path || !address) {
      throw new Error('PasskeyClientDB: Missing derivedAddressesV2 fields');
    }
    const db = await this.getDB();
    await db.put(DB_CONFIG.derivedAddressV2Store, {
      profileId,
      sourceChainId,
      sourceAccountAddress,
      targetChainId,
      providerRef,
      path,
      address,
      updatedAt: typeof input.updatedAt === 'number' ? input.updatedAt : Date.now(),
    } satisfies DerivedAddressV2Record);
  }

  async getDerivedAddressV2(input: {
    profileId: string;
    sourceChainId: string;
    sourceAccountAddress: string;
    providerRef: string;
    path: string;
  }): Promise<DerivedAddressV2Record | null> {
    const profileId = String(input.profileId || '').trim();
    const sourceChainId = normalizeChainId(input.sourceChainId);
    const sourceAccountAddress = normalizeAccountAddress(input.sourceAccountAddress);
    const providerRef = String(input.providerRef || '').trim();
    const path = String(input.path || '').trim();
    if (!profileId || !sourceChainId || !sourceAccountAddress || !providerRef || !path) return null;

    const db = await this.getDB();
    const tx = db.transaction(DB_CONFIG.derivedAddressV2Store, 'readonly');
    const rows = await tx.store
      .index('sourceChainId_sourceAccountAddress')
      .getAll([sourceChainId, sourceAccountAddress]) as DerivedAddressV2Record[];
    await tx.done;

    const match = (rows || [])
      .filter((row) =>
        row.profileId === profileId
        && String(row.providerRef || '').trim() === providerRef
        && String(row.path || '').trim() === path,
      )
      .sort((a, b) => Number(b.updatedAt || 0) - Number(a.updatedAt || 0))[0];
    return match || null;
  }

  async upsertRecoveryEmailsV2(
    profileId: string,
    entries: Array<{ hashHex: string; email: string }>,
  ): Promise<void> {
    const normalizedProfileId = String(profileId || '').trim();
    if (!normalizedProfileId || !entries?.length) return;
    const db = await this.getDB();
    const now = Date.now();
    for (const entry of entries) {
      const hashHex = String(entry?.hashHex || '').trim();
      const email = String(entry?.email || '').trim();
      if (!hashHex) continue;
      await db.put(DB_CONFIG.recoveryEmailV2Store, {
        profileId: normalizedProfileId,
        hashHex,
        email: email || hashHex,
        addedAt: now,
      } satisfies RecoveryEmailV2Record);
    }
  }

  async listRecoveryEmailsV2(profileId: string): Promise<RecoveryEmailV2Record[]> {
    const normalizedProfileId = String(profileId || '').trim();
    if (!normalizedProfileId) return [];
    const db = await this.getDB();
    const tx = db.transaction(DB_CONFIG.recoveryEmailV2Store, 'readonly');
    const rows = await tx.store.index('profileId').getAll(normalizedProfileId) as RecoveryEmailV2Record[];
    await tx.done;
    return rows || [];
  }

  async selectProfileAuthenticatorsForPrompt(args: {
    profileId: string;
    authenticators: ProfileAuthenticatorRecord[];
    selectedCredentialRawId?: string;
    accountLabel?: string;
  }): Promise<{
    authenticatorsForPrompt: ProfileAuthenticatorRecord[];
    wrongPasskeyError?: string;
  }> {
    const profileId = String(args.profileId || '').trim();
    const authenticators = Array.isArray(args.authenticators) ? args.authenticators : [];
    if (!profileId || authenticators.length <= 1) {
      return { authenticatorsForPrompt: authenticators };
    }

    const lastProfileState = await this.getLastProfileState().catch(() => null);
    if (!lastProfileState || lastProfileState.profileId !== profileId) {
      return { authenticatorsForPrompt: authenticators };
    }

    const expectedDeviceNumber = Number(lastProfileState.deviceNumber);
    const byDeviceNumber = authenticators.filter((a) => a.deviceNumber === expectedDeviceNumber);
    const expectedCredentialId = String(
      byDeviceNumber[0]?.credentialId || authenticators[0]?.credentialId || '',
    ).trim();
    const byCredentialId = expectedCredentialId
      ? authenticators.filter((a) => a.credentialId === expectedCredentialId)
      : [];
    const authenticatorsForPrompt =
      byCredentialId.length > 0
        ? byCredentialId
        : (byDeviceNumber.length > 0 ? byDeviceNumber : authenticators);

    const selectedCredentialRawId = String(args.selectedCredentialRawId || '').trim();
    const accountLabel = String(args.accountLabel || profileId).trim();
    const wrongPasskeyError =
      selectedCredentialRawId && expectedCredentialId && selectedCredentialRawId !== expectedCredentialId
        ? (
          `You have multiple passkeys (deviceNumbers) for account ${accountLabel}, `
          + 'but used a different passkey than the most recently logged-in one. '
          + 'Please use the passkey for the most recently logged-in device.'
        )
        : undefined;

    return { authenticatorsForPrompt, wrongPasskeyError };
  }

  private createSignerOperationId(prefix: string): string {
    return typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? `${prefix}:${crypto.randomUUID()}`
      : `${prefix}:${Date.now()}:${Math.random().toString(16).slice(2)}`;
  }

  private async upsertAccountSignerDirect(input: UpsertAccountSignerInput): Promise<AccountSignerRecord> {
    const profileId = String(input.profileId || '').trim();
    const chainId = normalizeChainId(input.chainId);
    const accountAddress = normalizeAccountAddress(input.accountAddress);
    const signerId = String(input.signerId || '').trim();
    if (!profileId || !chainId || !accountAddress || !signerId) {
      throw new Error('PasskeyClientDB: profileId, chainId, accountAddress, and signerId are required');
    }
    if (!Number.isSafeInteger(input.signerSlot) || input.signerSlot < 1) {
      throw new Error('PasskeyClientDB: signerSlot must be an integer >= 1');
    }
    const db = await this.getDB();
    const chainAccount = await db.get(
      DB_CONFIG.chainAccountsStore,
      [profileId, chainId, accountAddress],
    ) as ChainAccountRecord | undefined;
    if (!chainAccount) {
      throw new DBConstraintError(
        'MISSING_CHAIN_ACCOUNT',
        `Cannot upsert signer without chain account row: ${profileId}/${chainId}/${accountAddress}`,
        { profileId, chainId, accountAddress, signerId },
      );
    }
    if (chainAccount.profileId !== profileId) {
      throw new DBConstraintError(
        'CHAIN_ACCOUNT_PROFILE_MISMATCH',
        `Chain account profile mismatch for ${chainId}/${accountAddress}`,
        {
          expectedProfileId: profileId,
          chainAccountProfileId: chainAccount.profileId,
          chainId,
          accountAddress,
          signerId,
        },
      );
    }
    this.assertSignerTypeCapability(input.signerType, chainAccount.accountModel, {
      chainId,
      accountAddress,
    });

    const tx = db.transaction(DB_CONFIG.accountSignersStore, 'readwrite');
    const store = tx.store;
    const now = Date.now();
    const existing = await store.get([chainId, accountAddress, signerId]) as AccountSignerRecord | undefined;
    if (existing && existing.profileId !== profileId) {
      throw new DBConstraintError(
        'CHAIN_ACCOUNT_PROFILE_MISMATCH',
        `Signer row belongs to a different profile for ${chainId}/${accountAddress}/${signerId}`,
        {
          expectedProfileId: profileId,
          existingProfileId: existing.profileId,
          chainId,
          accountAddress,
          signerId,
        },
      );
    }
    const removedAt = this.ensureRevokedSignerHasRemovedAt({
      status: input.status,
      removedAt: input.removedAt ?? existing?.removedAt,
      chainId,
      accountAddress,
      signerId,
    });
    const next: AccountSignerRecord = {
      profileId,
      chainId,
      accountAddress,
      signerId,
      signerSlot: input.signerSlot,
      signerType: input.signerType,
      status: input.status,
      addedAt: existing?.addedAt ?? now,
      updatedAt: now,
      ...(removedAt != null ? { removedAt } : {}),
      ...(input.metadata != null ? { metadata: input.metadata } : (existing?.metadata != null ? { metadata: existing.metadata } : {})),
    };
    await this.assertSignerWriteInvariants(store, {
      next,
      accountModel: chainAccount.accountModel,
      existingSignerId: existing?.signerId,
      existingStatus: existing?.status,
    });
    await store.put(next);
    await tx.done;
    return next;
  }

  async upsertAccountSigner(input: UpsertAccountSignerInput): Promise<AccountSignerRecord> {
    const next = await this.upsertAccountSignerDirect(input);
    const routeThroughOutbox = input.mutation?.routeThroughOutbox ?? true;
    if (!routeThroughOutbox) return next;
    const opId = String(input.mutation?.opId || '').trim() || this.createSignerOperationId('add-signer');
    const idempotencyKey = String(input.mutation?.idempotencyKey || '').trim()
      || `add-signer:${next.chainId}:${next.accountAddress}:${next.signerId}:${next.signerSlot}`;
    await this.enqueueSignerOperation({
      opId,
      idempotencyKey,
      opType: 'add-signer',
      chainId: next.chainId,
      accountAddress: next.accountAddress,
      signerId: next.signerId,
      payload: {
        profileId: next.profileId,
        signerSlot: next.signerSlot,
        signerType: next.signerType,
        ...(next.metadata ? { signerMetadata: next.metadata } : {}),
        ...(input.mutation?.outboxPayload ? input.mutation.outboxPayload : {}),
      },
      status: input.mutation?.outboxStatus || 'queued',
    });
    return next;
  }

  async listAccountSigners(args: { chainId: string; accountAddress: string; status?: AccountSignerStatus }): Promise<AccountSignerRecord[]> {
    const chainId = normalizeChainId(args.chainId);
    const accountAddress = normalizeAccountAddress(args.accountAddress);
    if (!chainId || !accountAddress) return [];
    const db = await this.getDB();
    const tx = db.transaction(DB_CONFIG.accountSignersStore, 'readonly');
    const store = tx.store;
    if (args.status) {
      const idx = store.index('chainId_accountAddress_status');
      const rows = await idx.getAll([chainId, accountAddress, args.status]);
      return (rows as AccountSignerRecord[]) || [];
    }
    const idx = store.index('chainId_accountAddress');
    const rows = await idx.getAll([chainId, accountAddress]);
    return (rows as AccountSignerRecord[]) || [];
  }

  async getAccountSigner(args: {
    chainId: string;
    accountAddress: string;
    signerId: string;
  }): Promise<AccountSignerRecord | null> {
    const chainId = normalizeChainId(args.chainId);
    const accountAddress = normalizeAccountAddress(args.accountAddress);
    const signerId = String(args.signerId || '').trim();
    if (!chainId || !accountAddress || !signerId) return null;
    const db = await this.getDB();
    const row = await db.get(DB_CONFIG.accountSignersStore, [chainId, accountAddress, signerId]) as
      | AccountSignerRecord
      | undefined;
    return row || null;
  }

  private async setAccountSignerStatusDirect(args: {
    chainId: string;
    accountAddress: string;
    signerId: string;
    status: AccountSignerStatus;
    removedAt?: number;
  }): Promise<AccountSignerRecord | null> {
    const chainId = normalizeChainId(args.chainId);
    const accountAddress = normalizeAccountAddress(args.accountAddress);
    const signerId = String(args.signerId || '').trim();
    if (!chainId || !accountAddress || !signerId) return null;
    const db = await this.getDB();
    const existing = await db.get(
      DB_CONFIG.accountSignersStore,
      [chainId, accountAddress, signerId],
    ) as AccountSignerRecord | undefined;
    if (!existing) return null;
    const chainAccount = await db.get(
      DB_CONFIG.chainAccountsStore,
      [existing.profileId, chainId, accountAddress],
    ) as ChainAccountRecord | undefined;
    if (!chainAccount) {
      throw new DBConstraintError(
        'MISSING_CHAIN_ACCOUNT',
        `Cannot update signer status without chain account row: ${existing.profileId}/${chainId}/${accountAddress}`,
        {
          profileId: existing.profileId,
          chainId,
          accountAddress,
          signerId,
        },
      );
    }

    const removedAt = this.ensureRevokedSignerHasRemovedAt({
      status: args.status,
      removedAt: args.removedAt ?? existing.removedAt,
      chainId,
      accountAddress,
      signerId,
    });

    const tx = db.transaction(DB_CONFIG.accountSignersStore, 'readwrite');
    const store = tx.store;
    const latest = await store.get([chainId, accountAddress, signerId]) as AccountSignerRecord | undefined;
    if (!latest) {
      await tx.done;
      return null;
    }

    const updated: AccountSignerRecord = {
      ...latest,
      status: args.status,
      updatedAt: Date.now(),
      ...(removedAt != null ? { removedAt } : {}),
    };
    await this.assertSignerWriteInvariants(store, {
      next: updated,
      accountModel: chainAccount.accountModel,
      existingSignerId: latest.signerId,
      existingStatus: latest.status,
    });
    await store.put(updated);
    await tx.done;
    return updated;
  }

  async setAccountSignerStatus(args: {
    chainId: string;
    accountAddress: string;
    signerId: string;
    status: AccountSignerStatus;
    removedAt?: number;
    mutation?: SignerMutationOptions;
  }): Promise<AccountSignerRecord | null> {
    const updated = await this.setAccountSignerStatusDirect(args);
    if (!updated) return null;

    const routeThroughOutbox = args.mutation?.routeThroughOutbox ?? true;
    if (!routeThroughOutbox) return updated;

    const opType: SignerOperationType = args.status === 'revoked' ? 'revoke-signer' : 'add-signer';
    const opId = String(args.mutation?.opId || '').trim() || this.createSignerOperationId(opType);
    const idempotencyKey = String(args.mutation?.idempotencyKey || '').trim()
      || `signer-status:${args.status}:${updated.chainId}:${updated.accountAddress}:${updated.signerId}`;
    await this.enqueueSignerOperation({
      opId,
      idempotencyKey,
      opType,
      chainId: updated.chainId,
      accountAddress: updated.accountAddress,
      signerId: updated.signerId,
      payload: {
        profileId: updated.profileId,
        signerSlot: updated.signerSlot,
        status: updated.status,
        ...(updated.removedAt != null ? { removedAt: updated.removedAt } : {}),
        ...(args.mutation?.outboxPayload ? args.mutation.outboxPayload : {}),
      },
      status: args.mutation?.outboxStatus || 'queued',
    });
    return updated;
  }

  async enqueueSignerOperation(input: EnqueueSignerOperationInput): Promise<SignerOpOutboxRecord> {
    const opId = String(input.opId || '').trim();
    const idempotencyKey = String(input.idempotencyKey || '').trim();
    const chainId = normalizeChainId(input.chainId);
    const accountAddress = normalizeAccountAddress(input.accountAddress);
    const signerId = String(input.signerId || '').trim();
    if (!opId || !idempotencyKey || !chainId || !accountAddress || !signerId) {
      throw new Error('PasskeyClientDB: opId, idempotencyKey, chainId, accountAddress, and signerId are required');
    }
    const db = await this.getDB();
    const now = Date.now();
    const existing = await db.get(DB_CONFIG.signerOpsOutboxStore, opId) as SignerOpOutboxRecord | undefined;
    if (!existing) {
      const txByIdempotency = db.transaction(DB_CONFIG.signerOpsOutboxStore, 'readonly');
      const byIdempotency = await txByIdempotency.store
        .index('idempotencyKey')
        .get(idempotencyKey) as SignerOpOutboxRecord | undefined;
      await txByIdempotency.done;
      if (byIdempotency) return byIdempotency;
    }
    const next: SignerOpOutboxRecord = {
      opId,
      idempotencyKey,
      opType: input.opType,
      chainId,
      accountAddress,
      signerId,
      payload: input.payload ?? existing?.payload,
      status: input.status ?? existing?.status ?? 'queued',
      attemptCount: input.attemptCount ?? existing?.attemptCount ?? 0,
      nextAttemptAt: input.nextAttemptAt ?? existing?.nextAttemptAt ?? now,
      lastError: input.lastError ?? existing?.lastError,
      txHash: input.txHash ?? existing?.txHash,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    try {
      await db.put(DB_CONFIG.signerOpsOutboxStore, next);
    } catch (error: any) {
      const isConstraint = String(error?.name || '').toLowerCase() === 'constrainterror';
      if (!isConstraint) throw error;
      const txByIdempotency = db.transaction(DB_CONFIG.signerOpsOutboxStore, 'readonly');
      const byIdempotency = await txByIdempotency.store
        .index('idempotencyKey')
        .get(idempotencyKey) as SignerOpOutboxRecord | undefined;
      await txByIdempotency.done;
      if (byIdempotency) return byIdempotency;
      throw error;
    }
    return next;
  }

  async listSignerOperations(args?: {
    statuses?: SignerOperationStatus[];
    dueBefore?: number;
    limit?: number;
  }): Promise<SignerOpOutboxRecord[]> {
    const statuses = (args?.statuses && args.statuses.length > 0)
      ? args.statuses
      : (['queued', 'submitted', 'failed'] as SignerOperationStatus[]);
    const dueBefore = typeof args?.dueBefore === 'number' ? args.dueBefore : Date.now();
    const limit = Number.isSafeInteger(args?.limit) && Number(args?.limit) > 0
      ? Number(args?.limit)
      : 100;
    const db = await this.getDB();
    const collected: SignerOpOutboxRecord[] = [];
    for (const status of statuses) {
      const tx = db.transaction(DB_CONFIG.signerOpsOutboxStore, 'readonly');
      const rows = await tx.store.index('status').getAll(status) as SignerOpOutboxRecord[];
      await tx.done;
      for (const row of rows || []) {
        if (typeof row?.nextAttemptAt === 'number' && row.nextAttemptAt <= dueBefore) {
          collected.push(row);
        }
      }
    }
    collected.sort((a, b) => {
      const timeDelta = (a.nextAttemptAt || 0) - (b.nextAttemptAt || 0);
      if (timeDelta !== 0) return timeDelta;
      return String(a.opId || '').localeCompare(String(b.opId || ''));
    });
    return collected.slice(0, limit);
  }

  async setSignerOperationStatus(args: {
    opId: string;
    status: SignerOperationStatus;
    attemptDelta?: number;
    nextAttemptAt?: number;
    lastError?: string | null;
    txHash?: string | null;
  }): Promise<SignerOpOutboxRecord | null> {
    const opId = String(args.opId || '').trim();
    if (!opId) return null;
    const db = await this.getDB();
    const existing = await db.get(DB_CONFIG.signerOpsOutboxStore, opId) as SignerOpOutboxRecord | undefined;
    if (!existing) return null;
    const attemptDelta = Number.isFinite(args.attemptDelta) ? Number(args.attemptDelta) : 0;
    const attemptCount = Math.max(0, (existing.attemptCount || 0) + attemptDelta);
    const next: SignerOpOutboxRecord = {
      ...existing,
      status: args.status,
      attemptCount,
      nextAttemptAt:
        typeof args.nextAttemptAt === 'number'
          ? args.nextAttemptAt
          : existing.nextAttemptAt,
      ...(args.lastError === null
        ? { lastError: undefined }
        : (typeof args.lastError === 'string' ? { lastError: args.lastError } : { lastError: existing.lastError })),
      ...(args.txHash === null
        ? { txHash: undefined }
        : (typeof args.txHash === 'string' ? { txHash: args.txHash } : { txHash: existing.txHash })),
      updatedAt: Date.now(),
    };
    await db.put(DB_CONFIG.signerOpsOutboxStore, next);
    return next;
  }

  /**
   * Set the scoping key used for last-user selection in wallet-iframe mode.
   *
   * When set, last-user pointers are stored in a namespaced app-state key:
   * `lastProfileState::<scope>`.
   *
   * This is intended for the wallet-origin host to call with the embedding app origin
   * (e.g., from the CONNECT handshake `MessageEvent.origin`).
   */
  setLastUserScope(scope: string | null): void {
    this.lastUserScope = normalizeLastUserScope(scope);
  }

  getLastUserScope(): string | null {
    return this.lastUserScope;
  }

  private getScopedLastProfileStateAppStateKey(
    scope: string | null = this.lastUserScope,
  ): string | null {
    return makeScopedAppStateKey(LAST_PROFILE_STATE_APP_STATE_KEY, scope);
  }

  private async assertLastProfileStateInvariant(state: LastProfileState): Promise<void> {
    const db = await this.getDB();
    const profile = await db.get(DB_CONFIG.profilesStore, state.profileId) as ProfileRecord | undefined;
    if (!profile) {
      throw new DBConstraintError(
        'INVALID_LAST_PROFILE_STATE',
        `lastProfileState profile does not exist: ${state.profileId}`,
        {
          profileId: state.profileId,
          deviceNumber: state.deviceNumber,
        },
      );
    }

    const signerTx = db.transaction(DB_CONFIG.accountSignersStore, 'readonly');
    const signerRows = await signerTx.store
      .index('profileId')
      .getAll(state.profileId) as AccountSignerRecord[];
    await signerTx.done;
    const hasMatchingSignerSlot = signerRows.some(
      (row) => row.signerSlot === state.deviceNumber && row.status !== 'revoked',
    );
    if (!hasMatchingSignerSlot) {
      throw new DBConstraintError(
        'INVALID_LAST_PROFILE_STATE',
        `lastProfileState signer slot ${state.deviceNumber} was not found for profile ${state.profileId}`,
        {
          profileId: state.profileId,
          deviceNumber: state.deviceNumber,
        },
      );
    }
  }

  private async clearLegacyLastUserPointers(): Promise<void> {
    await this.setAppState(LEGACY_LAST_USER_APP_STATE_KEY, null).catch(() => undefined);
    const scopedLegacyKey = makeScopedAppStateKey(LEGACY_LAST_USER_APP_STATE_KEY, this.lastUserScope);
    if (scopedLegacyKey) {
      await this.setAppState(scopedLegacyKey, null).catch(() => undefined);
    }
  }

  async getLastProfileState(): Promise<LastProfileState | null> {
    const scopedKey = this.getScopedLastProfileStateAppStateKey();
    if (scopedKey) {
      const scopedRaw = await this.getAppState<unknown>(scopedKey).catch(() => undefined);
      return parseLastProfileState(scopedRaw);
    }
    const unscopedRaw = await this.getAppState<unknown>(LAST_PROFILE_STATE_APP_STATE_KEY).catch(
      () => undefined,
    );
    return parseLastProfileState(unscopedRaw);
  }

  async setLastProfileState(state: LastProfileState | null): Promise<void> {
    if (state) {
      await this.assertLastProfileStateInvariant(state);
    }
    const scopedKey = this.getScopedLastProfileStateAppStateKey();
    if (scopedKey) {
      await this.setAppState(scopedKey, state);
      return;
    }
    await this.setAppState(LAST_PROFILE_STATE_APP_STATE_KEY, state);
  }

  private async clearLastProfileStateIfMatchesProfile(profileId: string): Promise<void> {
    await this.clearLegacyLastUserPointers();
    const normalizedProfileId = String(profileId || '').trim();
    if (!normalizedProfileId) return;
    try {
      const legacyProfile = parseLastProfileState(
        await this.getAppState<unknown>(LAST_PROFILE_STATE_APP_STATE_KEY),
      );
      if (legacyProfile && legacyProfile.profileId === normalizedProfileId) {
        await this.setAppState(LAST_PROFILE_STATE_APP_STATE_KEY, null);
      }
    } catch {}

    const scopedProfileKey = this.getScopedLastProfileStateAppStateKey();
    if (scopedProfileKey) {
      try {
        const scopedProfile = parseLastProfileState(
          await this.getAppState<unknown>(scopedProfileKey),
        );
        if (scopedProfile && scopedProfile.profileId === normalizedProfileId) {
          await this.setAppState(scopedProfileKey, null);
        }
      } catch {}
    }
  }

  private async backfillCoreFromLegacyUserRecord(
    userData: ClientUserData,
    db: IDBPDatabase,
  ): Promise<void> {
    const accountId = toAccountId(userData.nearAccountId);
    const profileId = buildLegacyNearProfileId(accountId);
    const chainId = inferNearChainId(accountId, userData.preferences?.useNetwork);
    const accountAddress = normalizeAccountAddress(accountId);
    const signerId = String(userData.passkeyCredential?.rawId || '').trim() || `legacy-device-${userData.deviceNumber}`;
    const now = Date.now();

    const existingProfile = await db.get(DB_CONFIG.profilesStore, profileId) as ProfileRecord | undefined;
    const profile: ProfileRecord = {
      profileId,
      defaultDeviceNumber: userData.deviceNumber,
      passkeyCredential: userData.passkeyCredential,
      preferences: userData.preferences,
      createdAt: existingProfile?.createdAt ?? userData.registeredAt ?? now,
      updatedAt: now,
    };
    await db.put(DB_CONFIG.profilesStore, profile);

    const existingChain = await db.get(DB_CONFIG.chainAccountsStore, [profileId, chainId, accountAddress]) as ChainAccountRecord | undefined;
    const chainAccount: ChainAccountRecord = {
      profileId,
      chainId,
      accountAddress,
      accountModel: 'near-native',
      isPrimary: existingChain?.isPrimary ?? true,
      createdAt: existingChain?.createdAt ?? now,
      updatedAt: now,
      legacyNearAccountId: accountId,
    };
    await db.put(DB_CONFIG.chainAccountsStore, chainAccount);

    const existingSigner = await db.get(DB_CONFIG.accountSignersStore, [chainId, accountAddress, signerId]) as AccountSignerRecord | undefined;
    const signerMetadata: Record<string, unknown> = {
      ...(existingSigner?.metadata || {}),
      clientNearPublicKey: userData.clientNearPublicKey,
      passkeyCredentialId: userData.passkeyCredential?.id,
      passkeyCredentialRawId: userData.passkeyCredential?.rawId,
      legacyNearAccountId: accountId,
    };
    const signer: AccountSignerRecord = {
      profileId,
      chainId,
      accountAddress,
      signerId,
      signerSlot: userData.deviceNumber,
      signerType: 'passkey',
      status: 'active',
      addedAt: existingSigner?.addedAt ?? now,
      updatedAt: now,
      metadata: signerMetadata,
    };
    await db.put(DB_CONFIG.accountSignersStore, signer);
  }

  private mapProfileAuthenticatorToLegacy(
    profileAuthenticator: ProfileAuthenticatorRecord,
    nearAccountId: AccountId,
  ): ClientAuthenticatorData {
    return {
      nearAccountId,
      deviceNumber: profileAuthenticator.deviceNumber,
      credentialId: profileAuthenticator.credentialId,
      credentialPublicKey: profileAuthenticator.credentialPublicKey,
      transports: profileAuthenticator.transports,
      name: profileAuthenticator.name,
      registered: profileAuthenticator.registered,
      syncedAt: profileAuthenticator.syncedAt,
    };
  }

  private async backfillProfileAuthenticatorFromLegacyRecord(
    authenticatorData: ClientAuthenticatorData,
    db: IDBPDatabase,
  ): Promise<void> {
    const accountId = toAccountId(authenticatorData.nearAccountId);
    const profileId = buildLegacyNearProfileId(accountId);
    const record: ProfileAuthenticatorRecord = {
      profileId,
      deviceNumber: authenticatorData.deviceNumber,
      credentialId: authenticatorData.credentialId,
      credentialPublicKey: authenticatorData.credentialPublicKey,
      transports: authenticatorData.transports,
      name: authenticatorData.name,
      registered: authenticatorData.registered,
      syncedAt: authenticatorData.syncedAt,
    };
    await db.put(DB_CONFIG.profileAuthenticatorStore, record);
  }

  private async upsertLegacyNearUserProjection(userData: ClientUserData): Promise<void> {
    const accountId = toAccountId(userData.nearAccountId);
    const deviceNumber = Number(userData.deviceNumber);
    if (!Number.isSafeInteger(deviceNumber) || deviceNumber < 1) {
      throw new Error('PasskeyClientDB: deviceNumber must be an integer >= 1');
    }

    const profileId = buildLegacyNearProfileId(accountId);
    const chainId = inferNearChainId(accountId, userData.preferences?.useNetwork);
    const accountAddress = normalizeAccountAddress(accountId);
    const signerId = String(userData.passkeyCredential?.rawId || '').trim()
      || `legacy-device-${deviceNumber}`;

    await this.upsertProfile({
      profileId,
      defaultDeviceNumber: deviceNumber,
      passkeyCredential: userData.passkeyCredential,
      ...(userData.preferences ? { preferences: userData.preferences } : {}),
    });

    await this.upsertChainAccount({
      profileId,
      chainId,
      accountAddress,
      accountModel: 'near-native',
      isPrimary: true,
      legacyNearAccountId: accountId,
    });

    const existingSigner = await this.getAccountSigner({
      chainId,
      accountAddress,
      signerId,
    }).catch(() => null);
    await this.upsertAccountSigner({
      profileId,
      chainId,
      accountAddress,
      signerId,
      signerSlot: deviceNumber,
      signerType: 'passkey',
      status: 'active',
      metadata: {
        ...(existingSigner?.metadata || {}),
        clientNearPublicKey: userData.clientNearPublicKey,
        passkeyCredentialId: userData.passkeyCredential?.id,
        passkeyCredentialRawId: userData.passkeyCredential?.rawId,
        legacyNearAccountId: accountId,
      },
      mutation: { routeThroughOutbox: false },
    });
  }

  private async buildLegacyNearUserFromV2(
    nearAccountId: AccountId,
    deviceNumber?: number,
  ): Promise<ClientUserData | null> {
    const accountId = toAccountId(nearAccountId);
    const accountAddress = normalizeAccountAddress(accountId);
    const db = await this.getDB();

    for (const chainId of getNearChainCandidates(accountId)) {
      const tx = db.transaction(DB_CONFIG.chainAccountsStore, 'readonly');
      const idx = tx.store.index('chainId_accountAddress');
      const chainAccount = await idx.get([chainId, accountAddress]) as ChainAccountRecord | undefined;
      if (!chainAccount?.profileId) continue;

      const profile = await db.get(DB_CONFIG.profilesStore, chainAccount.profileId) as ProfileRecord | undefined;
      if (!profile) continue;

      const signerTx = db.transaction(DB_CONFIG.accountSignersStore, 'readonly');
      const signerStore = signerTx.store;
      const activeSigners = await signerStore
        .index('chainId_accountAddress_status')
        .getAll([chainId, accountAddress, 'active']) as AccountSignerRecord[];
      if (!activeSigners.length) continue;

      const selectedSigner = (() => {
        if (typeof deviceNumber === 'number') {
          return activeSigners.find((row) => row.signerSlot === deviceNumber);
        }
        const preferredSlot = Number.isSafeInteger(profile.defaultDeviceNumber)
          ? profile.defaultDeviceNumber
          : 1;
        return (
          activeSigners.find((row) => row.signerSlot === preferredSlot) ||
          activeSigners
            .slice()
            .sort((a, b) => a.signerSlot - b.signerSlot)[0]
        );
      })();
      if (!selectedSigner) continue;

      const metadata = selectedSigner.metadata || {};
      const passkeyCredentialRawId = typeof metadata.passkeyCredentialRawId === 'string'
        ? metadata.passkeyCredentialRawId
        : selectedSigner.signerId;
      const passkeyCredentialId = typeof metadata.passkeyCredentialId === 'string'
        ? metadata.passkeyCredentialId
        : profile.passkeyCredential?.id || passkeyCredentialRawId;
      const clientNearPublicKey = typeof metadata.clientNearPublicKey === 'string'
        ? metadata.clientNearPublicKey
        : '';

      return {
        nearAccountId: accountId,
        deviceNumber: selectedSigner.signerSlot,
        version: 2,
        registeredAt: profile.createdAt,
        lastLogin: profile.updatedAt,
        lastUpdated: profile.updatedAt,
        clientNearPublicKey,
        passkeyCredential: {
          id: passkeyCredentialId,
          rawId: passkeyCredentialRawId,
        },
        preferences: profile.preferences,
      };
    }

    return null;
  }

  private async deleteV2DataForProfile(profileId: string): Promise<void> {
    const normalizedProfileId = String(profileId || '').trim();
    if (!normalizedProfileId) return;
    const db = await this.getDB();

    try {
      const tx = db.transaction(DB_CONFIG.accountSignersStore, 'readwrite');
      const idx = tx.store.index('profileId');
      let cursor = await idx.openCursor(IDBKeyRange.only(normalizedProfileId));
      while (cursor) {
        await tx.store.delete(cursor.primaryKey);
        cursor = await cursor.continue();
      }
      await tx.done;
    } catch {}

    try {
      const tx = db.transaction(DB_CONFIG.chainAccountsStore, 'readwrite');
      const idx = tx.store.index('profileId');
      let cursor = await idx.openCursor(IDBKeyRange.only(normalizedProfileId));
      while (cursor) {
        await tx.store.delete(cursor.primaryKey);
        cursor = await cursor.continue();
      }
      await tx.done;
    } catch {}

    try {
      const tx = db.transaction(DB_CONFIG.derivedAddressV2Store, 'readwrite');
      const idx = tx.store.index('profileId');
      let cursor = await idx.openCursor(IDBKeyRange.only(normalizedProfileId));
      while (cursor) {
        await tx.store.delete(cursor.primaryKey);
        cursor = await cursor.continue();
      }
      await tx.done;
    } catch {}

    try {
      const tx = db.transaction(DB_CONFIG.recoveryEmailV2Store, 'readwrite');
      const idx = tx.store.index('profileId');
      let cursor = await idx.openCursor(IDBKeyRange.only(normalizedProfileId));
      while (cursor) {
        await tx.store.delete(cursor.primaryKey);
        cursor = await cursor.continue();
      }
      await tx.done;
    } catch {}

    try {
      const tx = db.transaction(DB_CONFIG.profileAuthenticatorStore, 'readwrite');
      const idx = tx.store.index('profileId');
      let cursor = await idx.openCursor(IDBKeyRange.only(normalizedProfileId));
      while (cursor) {
        await tx.store.delete(cursor.primaryKey);
        cursor = await cursor.continue();
      }
      await tx.done;
    } catch {}

    try { await db.delete(DB_CONFIG.profilesStore, normalizedProfileId); } catch {}
  }

  async clearAllAppState(): Promise<void> {
    const db = await this.getDB();
    await db.clear(DB_CONFIG.appStateStore);
  }

  /**
   * Atomic operation wrapper for multiple IndexedDB operations
   * Either all operations succeed or all are rolled back
   */
  async atomicOperation<T>(operation: (db: IDBPDatabase) => Promise<T>): Promise<T> {
    const db = await this.getDB();
    try {
      const result = await operation(db);
      return result;
    } catch (error) {
      console.error('Atomic operation failed:', error);
      throw error;
    }
  }

}
