import type { IDBPDatabase } from 'idb';
import { toTrimmedString } from '../../../../../shared/src/utils/validation';
import { toAccountId } from '../../types/accountIds';
import type {
  ChainAccountRecord,
  ClientAuthenticatorData,
  ClientUserData,
  DerivedAddressRecord,
  DerivedAddressV2Record,
  LastProfileState,
  RecoveryEmailRecord,
  RecoveryEmailV2Record,
} from '../passkeyClientDB.types';
import type {
  DbMultichainMigrationParity,
  InvariantValidationSummary,
} from './invariants';
import {
  DB_CONFIG,
  DB_MULTICHAIN_MIGRATION_CHECKPOINTS_KEY,
  DB_MULTICHAIN_MIGRATION_HEARTBEAT_INTERVAL_MS,
  DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION,
  DB_MULTICHAIN_MIGRATION_STATE_KEY,
  LAST_PROFILE_STATE_APP_STATE_KEY,
  LEGACY_DERIVED_ADDRESS_STORE,
  LEGACY_LAST_USER_APP_STATE_KEY,
  LEGACY_RECOVERY_EMAIL_STORE,
} from './schema';
import {
  buildLegacyNearProfileId,
  inferNearChainId,
  inferTargetChainIdFromLegacyDerivedAddress,
  parseLastProfileState,
  parseLegacyLastUserState,
} from './nearCompat';

// Internal helper: legacy user records may be missing deviceNumber.
type ClientUserDataWithOptionalDevice =
  | ClientUserData
  | (Omit<ClientUserData, 'deviceNumber'> & { deviceNumber?: number });

export interface DbMultichainMigrationState {
  status: 'running' | 'completed' | 'failed';
  schemaVersion: number;
  startedAt: number;
  finishedAt?: number;
  counts: DbMultichainMigrationCounts;
  checkpoints?: DbMultichainMigrationCheckpoints;
  error?: string;
}

export type DbMultichainMigrationStep =
  | 'legacyUsersToCoreV2'
  | 'legacyAuthenticatorsToProfileAuthenticators'
  | 'legacyDerivedAddressesToV2'
  | 'legacyRecoveryEmailsToV2'
  | 'lastProfileStateSync'
  | 'smartAccountChainDefaultsBackfilled'
  | 'parityChecksLogged'
  | 'invariantsValidatedAndQuarantined';

export type DbMultichainMigrationCheckpoints = Partial<Record<
  DbMultichainMigrationStep,
  {
    status: 'completed';
    completedAt: number;
    counts?: Record<string, number>;
  }
>>;

export interface DbMultichainMigrationCounts {
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
  smartAccountRowsScanned: number;
  smartAccountRowsBackfilled: number;
  invariantRowsChecked: number;
  invariantViolationsFound: number;
  invariantRowsQuarantined: number;
}

export interface DbMultichainMigrationLock {
  ownerTabId: string;
  acquiredAt: number;
  heartbeatAt: number;
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
    smartAccountRowsScanned: 0,
    smartAccountRowsBackfilled: 0,
    invariantRowsChecked: 0,
    invariantViolationsFound: 0,
    invariantRowsQuarantined: 0,
  };
}

function normalizeAccountModel(value: unknown): string {
  return toTrimmedString(value || '').toLowerCase();
}

function normalizeAccountAddress(value: unknown): string {
  return toTrimmedString(value || '').toLowerCase();
}

function hasSmartAccountShape(row: ChainAccountRecord): boolean {
  const accountModel = normalizeAccountModel(row.accountModel);
  return (
    accountModel === 'erc4337'
    || accountModel === 'tempo-native'
    || toTrimmedString((row as any)?.factory || '').length > 0
    || toTrimmedString((row as any)?.entryPoint || '').length > 0
    || toTrimmedString((row as any)?.salt || '').length > 0
    || toTrimmedString((row as any)?.counterfactualAddress || '').length > 0
  );
}

export interface RunMigrationsIfNeededArgs {
  db: IDBPDatabase;
  lastUserScope: string | null;
  getAppStateFromDb: (db: IDBPDatabase, key: string) => Promise<unknown | undefined>;
  setAppStateInDb: (db: IDBPDatabase, key: string, value: unknown) => Promise<void>;
  setLastProfileStateInDb: (
    db: IDBPDatabase,
    state: LastProfileState | null,
    scope?: string | null,
  ) => Promise<void>;
  createMigrationOwnerId: () => string;
  tryAcquireMigrationLeaseInAppState: (
    db: IDBPDatabase,
    ownerTabId: string,
    acquiredAt: number,
  ) => Promise<boolean>;
  refreshMigrationLeaseInAppState: (
    db: IDBPDatabase,
    ownerTabId: string,
    acquiredAt: number,
  ) => Promise<void>;
  clearMigrationLeaseInAppState: (
    db: IDBPDatabase,
    ownerTabId: string,
  ) => Promise<void>;
  tryRunWithNavigatorMigrationLock: (
    runner: () => Promise<void>,
  ) => Promise<'executed' | 'unavailable' | 'unsupported'>;
  backfillCoreFromLegacyUserRecord: (userData: ClientUserData, db: IDBPDatabase) => Promise<void>;
  backfillProfileAuthenticatorFromLegacyRecord: (
    authenticatorData: ClientAuthenticatorData,
    db: IDBPDatabase,
  ) => Promise<void>;
  collectMigrationParity: (db: IDBPDatabase) => Promise<DbMultichainMigrationParity>;
  validateAndQuarantineInvariantViolations: (
    db: IDBPDatabase,
  ) => Promise<InvariantValidationSummary>;
}

export async function runMigrationsIfNeeded(args: RunMigrationsIfNeededArgs): Promise<void> {
  const { db } = args;

  const existing = await args.getAppStateFromDb(
    db,
    DB_MULTICHAIN_MIGRATION_STATE_KEY,
  ).catch(() => undefined) as DbMultichainMigrationState | undefined;
  const existingVersion = Number(existing?.schemaVersion || 1);
  if (
    existing?.status === 'completed' &&
    existingVersion >= DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION
  ) {
    return;
  }

  const ownerTabId = args.createMigrationOwnerId();
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
    await args.refreshMigrationLeaseInAppState(db, ownerTabId, acquiredAt);
    lastHeartbeatAt = now;
  };

  const persistRunningState = async (): Promise<void> => {
    await args.setAppStateInDb(db, DB_MULTICHAIN_MIGRATION_STATE_KEY, {
      status: 'running',
      schemaVersion: DB_MULTICHAIN_MIGRATION_SCHEMA_VERSION,
      startedAt,
      counts,
      checkpoints,
    } satisfies DbMultichainMigrationState);
    await args.setAppStateInDb(db, DB_MULTICHAIN_MIGRATION_CHECKPOINTS_KEY, checkpoints);
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
    const leaseAcquired = await args.tryAcquireMigrationLeaseInAppState(
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
        let stepSuccess = 0;
        let stepFailures = 0;
        if (db.objectStoreNames.contains(DB_CONFIG.userStore)) {
          const userTx = db.transaction(DB_CONFIG.userStore, 'readonly');
          let userCursor = await userTx.store.openCursor();
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
              const credentialRawId = toTrimmedString((raw as any)?.passkeyCredential?.rawId || '');
              const credentialId = toTrimmedString((raw as any)?.passkeyCredential?.id || '');
              const clientNearPublicKey = toTrimmedString((raw as any)?.clientNearPublicKey || '');
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
              await args.backfillCoreFromLegacyUserRecord(normalized, db);
              stepSuccess += 1;
              counts.coreUserBackfillSuccess += 1;
            } catch {
              stepFailures += 1;
              counts.coreUserBackfillFailures += 1;
            }
            userCursor = await current.continue();
          }
          await userTx.done;
        }
        await markCheckpoint('legacyUsersToCoreV2', {
          success: stepSuccess,
          failures: stepFailures,
        });
      }

      if (!checkpoints.legacyAuthenticatorsToProfileAuthenticators) {
        let stepUpserts = 0;
        let stepFailures = 0;
        if (db.objectStoreNames.contains(DB_CONFIG.authenticatorStore)) {
          const authTx = db.transaction(DB_CONFIG.authenticatorStore, 'readonly');
          let authCursor = await authTx.store.openCursor();
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
              const credentialId = toTrimmedString((legacy as any)?.credentialId || '');
              const credentialPublicKey = (legacy as any)?.credentialPublicKey;
              if (!credentialId || !(credentialPublicKey instanceof Uint8Array)) {
                stepFailures += 1;
                counts.profileAuthenticatorFailures += 1;
                authCursor = await current.continue();
                continue;
              }
              await args.backfillProfileAuthenticatorFromLegacyRecord(
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
        }
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
              const providerRef = toTrimmedString(legacy.contractId || '');
              const path = toTrimmedString(legacy.path || '');
              const address = toTrimmedString(legacy.address || '');
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
                sourceAccountAddress: toTrimmedString(accountId || '').toLowerCase(),
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
              const hashHex = toTrimmedString(legacy.hashHex || '');
              if (!hashHex) {
                stepFailures += 1;
                counts.recoveryEmailV2Failures += 1;
                recoveryCursor = await current.continue();
                continue;
              }
              const row: RecoveryEmailV2Record = {
                profileId: buildLegacyNearProfileId(accountId),
                hashHex,
                email: toTrimmedString(legacy.email || '') || hashHex,
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
        const lastProfileRaw = await args.getAppStateFromDb(
          db,
          LAST_PROFILE_STATE_APP_STATE_KEY,
        );
        const lastProfileState = parseLastProfileState(lastProfileRaw);
        if (!lastProfileState) {
          const lastUserRaw = await args.getAppStateFromDb(
            db,
            LEGACY_LAST_USER_APP_STATE_KEY,
          );
          const lastUserState = parseLegacyLastUserState(lastUserRaw);
          if (lastUserState) {
            await args.setLastProfileStateInDb(db, {
              profileId: buildLegacyNearProfileId(lastUserState.accountId),
              deviceNumber: lastUserState.deviceNumber,
              ...(args.lastUserScope != null ? { scope: args.lastUserScope } : {}),
            });
            counts.lastProfileStateSynced += 1;
          }
        }
        await markCheckpoint('lastProfileStateSync', {
          synced: counts.lastProfileStateSynced,
        });
      }

      if (!checkpoints.smartAccountChainDefaultsBackfilled) {
        let stepScanned = 0;
        let stepBackfilled = 0;
        if (db.objectStoreNames.contains(DB_CONFIG.chainAccountsStore)) {
          const chainTx = db.transaction(DB_CONFIG.chainAccountsStore, 'readwrite');
          let chainCursor = await chainTx.store.openCursor();
          while (chainCursor) {
            const current = chainCursor;
            await refreshHeartbeat();
            const row = current.value as ChainAccountRecord;
            if (hasSmartAccountShape(row)) {
              stepScanned += 1;
              counts.smartAccountRowsScanned += 1;
              const accountAddress = normalizeAccountAddress(row.accountAddress);
              const existingCounterfactual = normalizeAccountAddress(
                (row as any)?.counterfactualAddress,
              );
              const counterfactualAddress = existingCounterfactual || accountAddress;
              const hasDeployed = typeof (row as any)?.deployed === 'boolean';
              if (!hasDeployed || counterfactualAddress !== existingCounterfactual) {
                await current.update({
                  ...row,
                  counterfactualAddress,
                  deployed: hasDeployed ? (row as any).deployed : false,
                  updatedAt:
                    typeof (row as any)?.updatedAt === 'number'
                      ? (row as any).updatedAt
                      : Date.now(),
                } as ChainAccountRecord);
                stepBackfilled += 1;
                counts.smartAccountRowsBackfilled += 1;
              }
            }
            chainCursor = await current.continue();
          }
          await chainTx.done;
        }
        await markCheckpoint('smartAccountChainDefaultsBackfilled', {
          scanned: stepScanned,
          backfilled: stepBackfilled,
        });
      }

      if (!checkpoints.parityChecksLogged) {
        const parity = await args.collectMigrationParity(db);
        await markCheckpoint('parityChecksLogged', {
          mismatches: parity.mismatches.length,
        });
        console.info('PasskeyClientDB: migration parity summary', parity);
      }

      if (!checkpoints.invariantsValidatedAndQuarantined) {
        const invariantSummary = await args.validateAndQuarantineInvariantViolations(db);
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
      await args.setAppStateInDb(db, DB_MULTICHAIN_MIGRATION_STATE_KEY, completedState);
      await args.setAppStateInDb(db, DB_MULTICHAIN_MIGRATION_CHECKPOINTS_KEY, checkpoints);
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
      await args.setAppStateInDb(db, DB_MULTICHAIN_MIGRATION_STATE_KEY, failedState).catch(
        () => undefined,
      );
      console.error('PasskeyClientDB: multichain migration failed', {
        durationMs: finishedAt - startedAt,
        error: failedState.error,
        counts,
      });
      throw error;
    } finally {
      await args.clearMigrationLeaseInAppState(db, ownerTabId).catch(() => undefined);
    }
  };

  const lockOutcome = await args.tryRunWithNavigatorMigrationLock(runMigration);
  if (lockOutcome === 'unsupported') {
    await runMigration();
    return;
  }
  if (lockOutcome === 'unavailable') {
    console.info('PasskeyClientDB: skipping migration; navigator lock held by another tab');
  }
}
