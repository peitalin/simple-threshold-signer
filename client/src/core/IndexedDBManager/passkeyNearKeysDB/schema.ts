import type { IDBPDatabase } from 'idb';

export interface PasskeyNearKeysDBConfig {
  dbName: string;
  dbVersion: number;
  v2StoreName: string;
  v2KeyPath: string | string[];
}

export const DB_CONFIG: PasskeyNearKeysDBConfig = {
  dbName: 'PasskeyNearKeys',
  // v7: cutover to V2-only key material store; drop legacy keyMaterial store
  dbVersion: 7,
  v2StoreName: 'keyMaterialV2',
  v2KeyPath: ['profileId', 'deviceNumber', 'chainId', 'keyKind'],
} as const;

function ensureV2StoreIndexes(store: any): void {
  try {
    store.createIndex(
      'profileId_deviceNumber',
      ['profileId', 'deviceNumber'],
      { unique: false },
    );
  } catch {}
  try {
    store.createIndex(
      'chainId_keyKind',
      ['chainId', 'keyKind'],
      { unique: false },
    );
  } catch {}
  try { store.createIndex('publicKey', 'publicKey', { unique: false }); } catch {}
}

export function upgradePasskeyNearKeysDBSchema(
  db: IDBPDatabase,
  transaction: any,
): void {
  if (!db.objectStoreNames.contains(DB_CONFIG.v2StoreName)) {
    const v2Store = db.createObjectStore(DB_CONFIG.v2StoreName, { keyPath: DB_CONFIG.v2KeyPath });
    ensureV2StoreIndexes(v2Store);
  } else {
    try {
      const existing = transaction.objectStore(DB_CONFIG.v2StoreName);
      ensureV2StoreIndexes(existing);
    } catch {}
  }

  // Stable cutover completed: remove legacy NEAR key store.
  try {
    if (db.objectStoreNames.contains('keyMaterial')) {
      db.deleteObjectStore('keyMaterial');
    }
  } catch {}
}
