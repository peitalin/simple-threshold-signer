import { openDB, type IDBPDatabase } from 'idb';
import type { AccountId } from '../../types/accountIds';
import { toAccountId } from '../../types/accountIds';
import { DEFAULT_CONFIRMATION_CONFIG } from '../../types/signer-worker';
import type {
  AccountAddress,
  AccountModel,
  AccountModelCapabilities,
  AccountRef,
  AccountSignerRecord,
  AccountSignerStatus,
  AccountSignerType,
  ChainAccountRecord,
  ChainId,
  ClientAuthenticatorData,
  ClientUserData,
  DBConstraintErrorCode,
  DerivedAddressV2Record,
  EnqueueSignerOperationInput,
  IndexedDBEvent,
  LastProfileState,
  ProfileAuthenticatorRecord,
  ProfileId,
  ProfileRecord,
  RecoveryEmailV2Record,
  SignerId,
  SignerMutationOptions,
  SignerOperationStatus,
  SignerOperationType,
  SignerOpOutboxRecord,
  StoreUserDataInput,
  UpsertAccountSignerInput,
  UpsertChainAccountInput,
  UpsertProfileInput,
  UserPreferences,
} from '../passkeyClientDB.types';
import {
  DB_CONFIG,
  DERIVED_ADDRESS_LOOKUP_INDEX,
  DB_MULTICHAIN_MIGRATION_LOCK_KEY,
  DB_MULTICHAIN_MIGRATION_LOCK_NAME,
  DB_MULTICHAIN_MIGRATION_LOCK_TTL_MS,
  DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION,
  LAST_PROFILE_STATE_APP_STATE_KEY,
  LEGACY_DERIVED_ADDRESS_STORE,
  LEGACY_LAST_USER_APP_STATE_KEY,
  LEGACY_NEAR_PROFILE_PREFIX,
  LEGACY_RECOVERY_EMAIL_STORE,
  type PasskeyClientDBConfig,
  upgradePasskeyClientDBSchema,
} from './schema';
import {
  createSignerOperationId as createSignerOperationIdValue,
  enqueueSignerOperationRecord,
  listSignerOperationRecords,
  setSignerOperationRecordStatus,
} from './outbox';
import {
  backfillCoreFromLegacyUserRecord as backfillCoreFromLegacyUserRecordValue,
  backfillProfileAuthenticatorFromLegacyRecord as backfillProfileAuthenticatorFromLegacyRecordValue,
  buildLegacyNearUserFromV2 as buildLegacyNearUserFromV2Value,
  getNearChainCandidates,
  inferNearChainId,
  mapProfileAuthenticatorToLegacy as mapProfileAuthenticatorToLegacyValue,
  parseLastProfileState,
  upsertLegacyNearUserProjection as upsertLegacyNearUserProjectionValue,
} from './nearCompat';
import {
  collectMigrationParity as collectMigrationParityValue,
  validateAndQuarantineInvariantViolations as validateAndQuarantineInvariantViolationsValue,
} from './invariants';
import {
  type DbMultichainMigrationLock,
  runMigrationsIfNeeded as runMigrationsIfNeededValue,
} from './migrations';
import { deleteV2ProfileData as deleteV2ProfileDataValue } from './profileCleanup';

export type {
  AccountAddress,
  AccountModel,
  AccountModelCapabilities,
  AccountRef,
  AccountSignerRecord,
  AccountSignerStatus,
  AccountSignerType,
  ChainAccountRecord,
  ChainId,
  ClientAuthenticatorData,
  ClientUserData,
  DBConstraintErrorCode,
  DerivedAddressRecord,
  DerivedAddressV2Record,
  EnqueueSignerOperationInput,
  IndexedDBEvent,
  LastProfileState,
  MigrationQuarantineRecord,
  ProfileAuthenticatorRecord,
  ProfileId,
  ProfileRecord,
  RecoveryEmailRecord,
  RecoveryEmailV2Record,
  SignerId,
  SignerMutationOptions,
  SignerOperationStatus,
  SignerOperationType,
  SignerOpOutboxRecord,
  StoreUserDataInput,
  UpsertAccountSignerInput,
  UpsertChainAccountInput,
  UpsertProfileInput,
  UserPreferences,
} from '../passkeyClientDB.types';

interface AppStateEntry<T = unknown> {
  key: string;
  value: T;
}

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

  // Events

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
          upgradePasskeyClientDBSchema(db, oldVersion, transaction);
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

  private async collectMigrationParity(db: IDBPDatabase) {
    return collectMigrationParityValue(db, {
      stores: {
        userStore: DB_CONFIG.userStore,
        authenticatorStore: DB_CONFIG.authenticatorStore,
        profileAuthenticatorStore: DB_CONFIG.profileAuthenticatorStore,
        profilesStore: DB_CONFIG.profilesStore,
        chainAccountsStore: DB_CONFIG.chainAccountsStore,
        accountSignersStore: DB_CONFIG.accountSignersStore,
        derivedAddressV2Store: DB_CONFIG.derivedAddressV2Store,
        recoveryEmailV2Store: DB_CONFIG.recoveryEmailV2Store,
      },
      legacyDerivedAddressStore: LEGACY_DERIVED_ADDRESS_STORE,
      legacyRecoveryEmailStore: LEGACY_RECOVERY_EMAIL_STORE,
      legacyNearProfilePrefix: LEGACY_NEAR_PROFILE_PREFIX,
    });
  }

  private async validateAndQuarantineInvariantViolations(
    db: IDBPDatabase,
  ): Promise<{ checked: number; violations: number; quarantined: number }> {
    return validateAndQuarantineInvariantViolationsValue(db, {
      stores: {
        appStateStore: DB_CONFIG.appStateStore,
        profileAuthenticatorStore: DB_CONFIG.profileAuthenticatorStore,
        profilesStore: DB_CONFIG.profilesStore,
        chainAccountsStore: DB_CONFIG.chainAccountsStore,
        accountSignersStore: DB_CONFIG.accountSignersStore,
        derivedAddressV2Store: DB_CONFIG.derivedAddressV2Store,
        recoveryEmailV2Store: DB_CONFIG.recoveryEmailV2Store,
        migrationQuarantineStore: DB_CONFIG.migrationQuarantineStore,
      },
      schemaVersion: DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION,
      lastProfileStateAppStateKey: LAST_PROFILE_STATE_APP_STATE_KEY,
      parseLastProfileState,
      allowedSignerStatuses: ALLOWED_SIGNER_STATUS_TRANSITIONS.pending,
    });
  }

  private async runMigrationsIfNeeded(db: IDBPDatabase): Promise<void> {
    await runMigrationsIfNeededValue({
      db,
      lastUserScope: this.lastUserScope,
      getAppStateFromDb: (targetDb, key) => this.getAppStateFromDb(targetDb, key),
      setAppStateInDb: (targetDb, key, value) => this.setAppStateInDb(targetDb, key, value),
      setLastProfileStateInDb: (targetDb, state, scope) =>
        this.setLastProfileStateInDb(targetDb, state, scope),
      createMigrationOwnerId: () => this.createMigrationOwnerId(),
      tryAcquireMigrationLeaseInAppState: (targetDb, ownerTabId, acquiredAt) =>
        this.tryAcquireMigrationLeaseInAppState(targetDb, ownerTabId, acquiredAt),
      refreshMigrationLeaseInAppState: (targetDb, ownerTabId, acquiredAt) =>
        this.refreshMigrationLeaseInAppState(targetDb, ownerTabId, acquiredAt),
      clearMigrationLeaseInAppState: (targetDb, ownerTabId) =>
        this.clearMigrationLeaseInAppState(targetDb, ownerTabId),
      tryRunWithNavigatorMigrationLock: (runner) => this.tryRunWithNavigatorMigrationLock(runner),
      backfillCoreFromLegacyUserRecord: (userData, targetDb) =>
        backfillCoreFromLegacyUserRecordValue({
          db: targetDb,
          userData,
          stores: {
            profilesStore: DB_CONFIG.profilesStore,
            chainAccountsStore: DB_CONFIG.chainAccountsStore,
            accountSignersStore: DB_CONFIG.accountSignersStore,
          },
        }),
      backfillProfileAuthenticatorFromLegacyRecord: (authenticatorData, targetDb) =>
        backfillProfileAuthenticatorFromLegacyRecordValue({
          db: targetDb,
          authenticatorData,
          profileAuthenticatorStore: DB_CONFIG.profileAuthenticatorStore,
        }),
      collectMigrationParity: (targetDb) => this.collectMigrationParity(targetDb),
      validateAndQuarantineInvariantViolations: (targetDb) =>
        this.validateAndQuarantineInvariantViolations(targetDb),
    });
  }

  // App state

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

  // V2 multichain records

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
    return rows.map((row) => mapProfileAuthenticatorToLegacyValue(row, accountId));
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
    return mapProfileAuthenticatorToLegacyValue(profileMatch, accountId);
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
      .index(DERIVED_ADDRESS_LOOKUP_INDEX)
      .getAll([profileId, sourceChainId, sourceAccountAddress, providerRef, path]) as DerivedAddressV2Record[];
    await tx.done;

    const match = (rows || [])
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
    return createSignerOperationIdValue(prefix);
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
    const db = await this.getDB();
    return enqueueSignerOperationRecord(db, DB_CONFIG.signerOpsOutboxStore, input);
  }

  async listSignerOperations(args?: {
    statuses?: SignerOperationStatus[];
    dueBefore?: number;
    limit?: number;
  }): Promise<SignerOpOutboxRecord[]> {
    const db = await this.getDB();
    return listSignerOperationRecords(db, DB_CONFIG.signerOpsOutboxStore, args);
  }

  async setSignerOperationStatus(args: {
    opId: string;
    status: SignerOperationStatus;
    attemptDelta?: number;
    nextAttemptAt?: number;
    lastError?: string | null;
    txHash?: string | null;
  }): Promise<SignerOpOutboxRecord | null> {
    const db = await this.getDB();
    return setSignerOperationRecordStatus(db, DB_CONFIG.signerOpsOutboxStore, args);
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

  private async upsertLegacyNearUserProjection(userData: ClientUserData): Promise<void> {
    await upsertLegacyNearUserProjectionValue({
      userData,
      ops: {
        upsertProfile: (input) => this.upsertProfile(input),
        upsertChainAccount: (input) => this.upsertChainAccount(input),
        getAccountSigner: (args) => this.getAccountSigner(args),
        upsertAccountSigner: (input) => this.upsertAccountSigner(input),
      },
    });
  }

  private async buildLegacyNearUserFromV2(
    nearAccountId: AccountId,
    deviceNumber?: number,
  ): Promise<ClientUserData | null> {
    const db = await this.getDB();
    return buildLegacyNearUserFromV2Value({
      db,
      nearAccountId,
      deviceNumber,
      stores: {
        chainAccountsStore: DB_CONFIG.chainAccountsStore,
        profilesStore: DB_CONFIG.profilesStore,
        accountSignersStore: DB_CONFIG.accountSignersStore,
      },
    });
  }

  private async deleteV2DataForProfile(profileId: string): Promise<void> {
    const db = await this.getDB();
    await deleteV2ProfileDataValue({
      db,
      profileId,
      stores: {
        profilesStore: DB_CONFIG.profilesStore,
        chainAccountsStore: DB_CONFIG.chainAccountsStore,
        accountSignersStore: DB_CONFIG.accountSignersStore,
        derivedAddressV2Store: DB_CONFIG.derivedAddressV2Store,
        recoveryEmailV2Store: DB_CONFIG.recoveryEmailV2Store,
        profileAuthenticatorStore: DB_CONFIG.profileAuthenticatorStore,
      },
    });
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
