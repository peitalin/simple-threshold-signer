import type { IDBPDatabase } from 'idb';
import { toTrimmedString } from '../../../../../shared/src/utils/validation';

async function deleteRowsByProfileId(args: {
  db: IDBPDatabase;
  storeName: string;
  profileId: string;
}): Promise<void> {
  const { db, storeName, profileId } = args;
  const tx = db.transaction(storeName, 'readwrite');
  const idx = tx.store.index('profileId');
  let cursor = await idx.openCursor(IDBKeyRange.only(profileId));
  while (cursor) {
    await tx.store.delete(cursor.primaryKey);
    cursor = await cursor.continue();
  }
  await tx.done;
}

export async function deleteV2ProfileData(args: {
  db: IDBPDatabase;
  profileId: string;
  stores: {
    profilesStore: string;
    chainAccountsStore: string;
    accountSignersStore: string;
    derivedAddressV2Store: string;
    recoveryEmailV2Store: string;
    profileAuthenticatorStore: string;
  };
}): Promise<void> {
  const { db, stores } = args;
  const normalizedProfileId = toTrimmedString(args.profileId || '');
  if (!normalizedProfileId) return;

  try {
    await deleteRowsByProfileId({
      db,
      storeName: stores.accountSignersStore,
      profileId: normalizedProfileId,
    });
  } catch {}

  try {
    await deleteRowsByProfileId({
      db,
      storeName: stores.chainAccountsStore,
      profileId: normalizedProfileId,
    });
  } catch {}

  try {
    await deleteRowsByProfileId({
      db,
      storeName: stores.derivedAddressV2Store,
      profileId: normalizedProfileId,
    });
  } catch {}

  try {
    await deleteRowsByProfileId({
      db,
      storeName: stores.recoveryEmailV2Store,
      profileId: normalizedProfileId,
    });
  } catch {}

  try {
    await deleteRowsByProfileId({
      db,
      storeName: stores.profileAuthenticatorStore,
      profileId: normalizedProfileId,
    });
  } catch {}

  try { await db.delete(stores.profilesStore, normalizedProfileId); } catch {}
}
