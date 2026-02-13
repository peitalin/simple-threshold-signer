import type { IDBPDatabase } from 'idb';
import { toAccountId } from '../../types/accountIds';
import type {
  AccountModel,
  AccountSignerRecord,
  AccountSignerStatus,
  ChainAccountRecord,
  DerivedAddressV2Record,
  LastProfileState,
  MigrationQuarantineRecord,
  ProfileAuthenticatorRecord,
  ProfileRecord,
  RecoveryEmailV2Record,
} from '../passkeyClientDB.types';

interface AppStateEntry<T = unknown> {
  key: string;
  value: T;
}

interface InvariantViolationRecord {
  sourceStore: string;
  sourcePrimaryKey: unknown;
  reason: string;
  record: unknown;
}

export interface DbMultichainMigrationParity {
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

export interface InvariantValidationSummary {
  checked: number;
  violations: number;
  quarantined: number;
}

export interface InvariantStores {
  userStore: string;
  appStateStore: string;
  authenticatorStore: string;
  profileAuthenticatorStore: string;
  profilesStore: string;
  chainAccountsStore: string;
  accountSignersStore: string;
  derivedAddressV2Store: string;
  recoveryEmailV2Store: string;
  migrationQuarantineStore: string;
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

function encodeDbPrimaryKey(primaryKey: unknown): string {
  try {
    return JSON.stringify(primaryKey);
  } catch {
    return String(primaryKey);
  }
}

async function countStoreRows(
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

async function collectLegacyUserStats(
  db: IDBPDatabase,
  userStore: string,
): Promise<{ legacyUsers: number; legacyUniqueAccounts: number }> {
  if (!db.objectStoreNames.contains(userStore)) {
    return { legacyUsers: 0, legacyUniqueAccounts: 0 };
  }
  const tx = db.transaction(userStore, 'readonly');
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

function isLegacyProfileId(profileId: unknown, legacyNearProfilePrefix: string): boolean {
  return String(profileId || '').startsWith(`${legacyNearProfilePrefix}:`);
}

async function quarantineInvariantViolation(
  db: IDBPDatabase,
  schemaVersion: number,
  migrationQuarantineStore: string,
  violation: InvariantViolationRecord,
): Promise<void> {
  const tx = db.transaction(
    [violation.sourceStore, migrationQuarantineStore],
    'readwrite',
  );
  const quarantine: MigrationQuarantineRecord = {
    sourceStore: violation.sourceStore,
    sourcePrimaryKey: encodeDbPrimaryKey(violation.sourcePrimaryKey),
    reason: violation.reason,
    record: violation.record,
    detectedAt: Date.now(),
    schemaVersion,
  };
  await tx.objectStore(migrationQuarantineStore).put(quarantine);
  await tx.objectStore(violation.sourceStore).delete(violation.sourcePrimaryKey as any);
  await tx.done;
}

export async function collectMigrationParity(
  db: IDBPDatabase,
  args: {
    stores: Pick<
      InvariantStores,
      | 'userStore'
      | 'authenticatorStore'
      | 'profileAuthenticatorStore'
      | 'profilesStore'
      | 'chainAccountsStore'
      | 'accountSignersStore'
      | 'derivedAddressV2Store'
      | 'recoveryEmailV2Store'
    >;
    legacyDerivedAddressStore: string;
    legacyRecoveryEmailStore: string;
    legacyNearProfilePrefix: string;
  },
): Promise<DbMultichainMigrationParity> {
  const { legacyUsers, legacyUniqueAccounts } = await collectLegacyUserStats(db, args.stores.userStore);
  const legacyAuthenticators = await countStoreRows(db, args.stores.authenticatorStore);
  const legacyDerivedAddresses = await countStoreRows(db, args.legacyDerivedAddressStore);
  const legacyRecoveryEmails = await countStoreRows(db, args.legacyRecoveryEmailStore);

  const v2Profiles = await countStoreRows(
    db,
    args.stores.profilesStore,
    (value) => isLegacyProfileId((value as ProfileRecord)?.profileId, args.legacyNearProfilePrefix),
  );
  const v2ChainAccounts = await countStoreRows(
    db,
    args.stores.chainAccountsStore,
    (value) => isLegacyProfileId((value as ChainAccountRecord)?.profileId, args.legacyNearProfilePrefix),
  );
  const v2AccountSigners = await countStoreRows(
    db,
    args.stores.accountSignersStore,
    (value) => isLegacyProfileId((value as AccountSignerRecord)?.profileId, args.legacyNearProfilePrefix),
  );
  const v2ProfileAuthenticators = await countStoreRows(
    db,
    args.stores.profileAuthenticatorStore,
    (value) => isLegacyProfileId((value as ProfileAuthenticatorRecord)?.profileId, args.legacyNearProfilePrefix),
  );
  const v2DerivedAddresses = await countStoreRows(
    db,
    args.stores.derivedAddressV2Store,
    (value) => isLegacyProfileId((value as DerivedAddressV2Record)?.profileId, args.legacyNearProfilePrefix),
  );
  const v2RecoveryEmails = await countStoreRows(
    db,
    args.stores.recoveryEmailV2Store,
    (value) => isLegacyProfileId((value as RecoveryEmailV2Record)?.profileId, args.legacyNearProfilePrefix),
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

export async function validateAndQuarantineInvariantViolations(
  db: IDBPDatabase,
  args: {
    stores: Pick<
      InvariantStores,
      | 'appStateStore'
      | 'profileAuthenticatorStore'
      | 'profilesStore'
      | 'chainAccountsStore'
      | 'accountSignersStore'
      | 'derivedAddressV2Store'
      | 'recoveryEmailV2Store'
      | 'migrationQuarantineStore'
    >;
    schemaVersion: number;
    lastProfileStateAppStateKey: string;
    parseLastProfileState: (raw: unknown) => LastProfileState | null;
    allowedSignerStatuses: ReadonlySet<AccountSignerStatus>;
  },
): Promise<InvariantValidationSummary> {
  const violations: InvariantViolationRecord[] = [];
  const seenViolationKeys = new Set<string>();
  const addViolation = (violation: InvariantViolationRecord): void => {
    const signature = `${violation.sourceStore}::${encodeDbPrimaryKey(violation.sourcePrimaryKey)}`;
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
    const tx = db.transaction(args.stores.profilesStore, 'readonly');
    let cursor = await tx.store.openCursor();
    while (cursor) {
      checked += 1;
      const row = cursor.value as ProfileRecord;
      const profileId = String(row?.profileId || '').trim();
      if (!profileId) {
        addViolation({
          sourceStore: args.stores.profilesStore,
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
    const tx = db.transaction(args.stores.chainAccountsStore, 'readonly');
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
          sourceStore: args.stores.chainAccountsStore,
          sourcePrimaryKey: cursor.primaryKey,
          reason: 'Missing profileId/chainId/accountAddress on chain account row',
          record: row,
        });
        cursor = await cursor.continue();
        continue;
      }
      if (!profileIds.has(profileId)) {
        addViolation({
          sourceStore: args.stores.chainAccountsStore,
          sourcePrimaryKey: cursor.primaryKey,
          reason: `Missing profile dependency: ${profileId}`,
          record: row,
        });
        cursor = await cursor.continue();
        continue;
      }
      if (!accountModel) {
        addViolation({
          sourceStore: args.stores.chainAccountsStore,
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
            sourceStore: args.stores.chainAccountsStore,
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
    const tx = db.transaction(args.stores.accountSignersStore, 'readonly');
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
          sourceStore: args.stores.accountSignersStore,
          sourcePrimaryKey: cursor.primaryKey,
          reason: 'Missing profileId/chainId/accountAddress/signerId on account signer row',
          record: row,
        });
        cursor = await cursor.continue();
        continue;
      }
      if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) {
        addViolation({
          sourceStore: args.stores.accountSignersStore,
          sourcePrimaryKey: cursor.primaryKey,
          reason: `Invalid signerSlot: ${String((row as any)?.signerSlot)}`,
          record: row,
        });
        cursor = await cursor.continue();
        continue;
      }
      if (!profileIds.has(profileId)) {
        addViolation({
          sourceStore: args.stores.accountSignersStore,
          sourcePrimaryKey: cursor.primaryKey,
          reason: `Missing profile dependency: ${profileId}`,
          record: row,
        });
        cursor = await cursor.continue();
        continue;
      }
      if (!chainAccounts.has(chainAccountKey(profileId, chainId, accountAddress))) {
        addViolation({
          sourceStore: args.stores.accountSignersStore,
          sourcePrimaryKey: cursor.primaryKey,
          reason: `Missing chain account dependency: ${profileId}/${chainId}/${accountAddress}`,
          record: row,
        });
        cursor = await cursor.continue();
        continue;
      }
      if (!args.allowedSignerStatuses.has(status) && status !== 'revoked') {
        addViolation({
          sourceStore: args.stores.accountSignersStore,
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
            sourceStore: args.stores.accountSignersStore,
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
            sourceStore: args.stores.accountSignersStore,
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
        sourceStore: args.stores.accountSignersStore,
        sourcePrimaryKey: rowRef.primaryKey,
        reason: `EOA account has multiple active signers for ${accountRef}`,
        record: rowRef.row,
      });
    }
  }

  {
    const tx = db.transaction(args.stores.profileAuthenticatorStore, 'readonly');
    let cursor = await tx.store.openCursor();
    while (cursor) {
      checked += 1;
      const row = cursor.value as ProfileAuthenticatorRecord;
      const profileId = String(row?.profileId || '').trim();
      const credentialId = String((row as any)?.credentialId || '').trim();
      const deviceNumber = Number((row as any)?.deviceNumber);
      if (!profileId || !credentialId) {
        addViolation({
          sourceStore: args.stores.profileAuthenticatorStore,
          sourcePrimaryKey: cursor.primaryKey,
          reason: 'Missing profileId/credentialId on profile authenticator row',
          record: row,
        });
        cursor = await cursor.continue();
        continue;
      }
      if (!Number.isSafeInteger(deviceNumber) || deviceNumber < 1) {
        addViolation({
          sourceStore: args.stores.profileAuthenticatorStore,
          sourcePrimaryKey: cursor.primaryKey,
          reason: `Invalid deviceNumber: ${String((row as any)?.deviceNumber)}`,
          record: row,
        });
        cursor = await cursor.continue();
        continue;
      }
      if (!profileIds.has(profileId)) {
        addViolation({
          sourceStore: args.stores.profileAuthenticatorStore,
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
    const tx = db.transaction(args.stores.derivedAddressV2Store, 'readonly');
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
          sourceStore: args.stores.derivedAddressV2Store,
          sourcePrimaryKey: cursor.primaryKey,
          reason: 'Missing required field(s) on derivedAddressV2 row',
          record: row,
        });
        cursor = await cursor.continue();
        continue;
      }
      if (!profileIds.has(profileId)) {
        addViolation({
          sourceStore: args.stores.derivedAddressV2Store,
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
    const tx = db.transaction(args.stores.recoveryEmailV2Store, 'readonly');
    let cursor = await tx.store.openCursor();
    while (cursor) {
      checked += 1;
      const row = cursor.value as RecoveryEmailV2Record;
      const profileId = String(row?.profileId || '').trim();
      const hashHex = String((row as any)?.hashHex || '').trim();
      if (!profileId || !hashHex) {
        addViolation({
          sourceStore: args.stores.recoveryEmailV2Store,
          sourcePrimaryKey: cursor.primaryKey,
          reason: 'Missing profileId/hashHex on recoveryEmailV2 row',
          record: row,
        });
        cursor = await cursor.continue();
        continue;
      }
      if (!profileIds.has(profileId)) {
        addViolation({
          sourceStore: args.stores.recoveryEmailV2Store,
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
    const tx = db.transaction(args.stores.appStateStore, 'readonly');
    let cursor = await tx.store.openCursor();
    while (cursor) {
      const row = cursor.value as AppStateEntry<unknown>;
      const key = String(row?.key || '').trim();
      if (
        key === args.lastProfileStateAppStateKey
        || key.startsWith(`${args.lastProfileStateAppStateKey}::`)
      ) {
        checked += 1;
        const parsed = args.parseLastProfileState(row?.value);
        if (!parsed) {
          addViolation({
            sourceStore: args.stores.appStateStore,
            sourcePrimaryKey: cursor.primaryKey,
            reason: `Invalid lastProfileState payload at key ${key}`,
            record: row,
          });
          cursor = await cursor.continue();
          continue;
        }
        if (!profileIds.has(parsed.profileId)) {
          addViolation({
            sourceStore: args.stores.appStateStore,
            sourcePrimaryKey: cursor.primaryKey,
            reason: `lastProfileState references missing profile ${parsed.profileId}`,
            record: row,
          });
          cursor = await cursor.continue();
          continue;
        }
        if (!profileSignerSlots.has(`${parsed.profileId}::${parsed.deviceNumber}`)) {
          addViolation({
            sourceStore: args.stores.appStateStore,
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
      await quarantineInvariantViolation(
        db,
        args.schemaVersion,
        args.stores.migrationQuarantineStore,
        violation,
      );
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
