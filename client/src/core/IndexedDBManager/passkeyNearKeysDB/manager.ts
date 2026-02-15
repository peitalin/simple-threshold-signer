import { openDB, type IDBPDatabase } from 'idb';
import { toTrimmedString } from '../../../../../shared/src/utils/validation';
import type {
  ClientShareDerivation,
  LocalNearSkV3Material,
  PasskeyChainKeyKind,
  PasskeyChainKeyMaterialV2,
  ThresholdEd25519_2p_V1Material,
} from '../passkeyNearKeysDB.types';
import {
  buildEnvelopeAAD,
  hydrateCompatibilityPayload as hydrateCompatibilityPayloadValue,
  normalizeLocalSkEnvelope,
  normalizePayloadEnvelope,
  sanitizePayload,
} from './envelope';
import {
  DB_CONFIG,
  type PasskeyNearKeysDBConfig,
  upgradePasskeyNearKeysDBSchema,
} from './schema';

export type {
  ClientShareDerivation,
  LocalNearSkV3Material,
  PasskeyChainKeyAlgorithm,
  PasskeyChainKeyKind,
  PasskeyChainKeyMaterialV2,
  PasskeyChainKeyPayloadEnvelope,
  PasskeyChainKeyPayloadEnvelopeAAD,
  PasskeyNearKeyMaterial,
  PasskeyNearKeyMaterialKind,
  ThresholdEd25519_2p_V1Material,
} from '../passkeyNearKeysDB.types';

export class PasskeyNearKeysDBManager {
  private config: PasskeyNearKeysDBConfig;
  private db: IDBPDatabase | null = null;
  private disabled = false;

  constructor(config: PasskeyNearKeysDBConfig = DB_CONFIG) {
    this.config = config;
  }

  getDbName(): string {
    return this.config.dbName;
  }

  setDbName(dbName: string): void {
    const next = toTrimmedString(dbName || '');
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

  /**
   * Get database connection, initializing if necessary
   */
  private async getDB(): Promise<IDBPDatabase> {
    if (this.disabled) {
      throw new Error('[PasskeyNearKeysDBManager] IndexedDB is disabled in this environment.');
    }
    if (this.db) {
      return this.db;
    }

    this.db = await openDB(this.config.dbName, this.config.dbVersion, {
      upgrade(db, _oldVersion, _newVersion, tx): void {
        upgradePasskeyNearKeysDBSchema(db, tx);
      },
      blocked() {
        console.warn('PasskeyNearKeysDB connection is blocked.');
      },
      blocking() {
        console.warn('PasskeyNearKeysDB connection is blocking another connection.');
      },
      terminated: () => {
        console.warn('PasskeyNearKeysDB connection has been terminated.');
        this.db = null;
      },
    });

    return this.db;
  }

  async storeKeyMaterialV2(data: PasskeyChainKeyMaterialV2): Promise<void> {
    const db = await this.getDB();
    const profileId = toTrimmedString(data.profileId || '');
    const signerId = toTrimmedString(data.signerId || '');
    const wrapKeySalt = toTrimmedString(data.wrapKeySalt || '');
    const chainId = toTrimmedString(data.chainId || '').toLowerCase();
    const keyKind = toTrimmedString(data.keyKind || '');
    const algorithm = toTrimmedString(data.algorithm || '');
    const publicKey = toTrimmedString(data.publicKey || '');
    if (!profileId) {
      throw new Error('PasskeyNearKeysDB: Missing profileId for keyMaterialV2');
    }
    if (!Number.isSafeInteger(data.deviceNumber) || data.deviceNumber < 1) {
      throw new Error('PasskeyNearKeysDB: Invalid deviceNumber for keyMaterialV2');
    }
    if (!chainId) {
      throw new Error('PasskeyNearKeysDB: Missing chainId for keyMaterialV2');
    }
    if (!keyKind) {
      throw new Error('PasskeyNearKeysDB: Missing keyKind for keyMaterialV2');
    }
    if (!algorithm) {
      throw new Error('PasskeyNearKeysDB: Missing algorithm for keyMaterialV2');
    }
    if (!publicKey) {
      throw new Error('PasskeyNearKeysDB: Missing publicKey for keyMaterialV2');
    }
    if (typeof data.timestamp !== 'number') {
      throw new Error('PasskeyNearKeysDB: Missing timestamp for keyMaterialV2');
    }
    if (!Number.isSafeInteger(data.schemaVersion) || data.schemaVersion < 1) {
      throw new Error('PasskeyNearKeysDB: Invalid schemaVersion for keyMaterialV2');
    }

    const payload = sanitizePayload(data.payload);
    const expectedAAD = buildEnvelopeAAD({
      profileId,
      deviceNumber: data.deviceNumber,
      chainId,
      keyKind,
      schemaVersion: data.schemaVersion,
      ...(signerId ? { signerId } : {}),
    });
    const payloadEnvelope = normalizePayloadEnvelope(
      data.payloadEnvelope,
      expectedAAD,
      `${profileId}/${data.deviceNumber}/${chainId}/${keyKind}`,
    );

    const normalizedLocalSkEnvelope = normalizeLocalSkEnvelope({
      keyKind,
      payload,
      payloadEnvelope,
      expectedAAD,
    });
    const storedPayload = normalizedLocalSkEnvelope.payload;
    const storedPayloadEnvelope = normalizedLocalSkEnvelope.payloadEnvelope;

    const toStore: PasskeyChainKeyMaterialV2 = {
      profileId,
      deviceNumber: data.deviceNumber,
      chainId,
      keyKind,
      algorithm,
      publicKey,
      ...(signerId ? { signerId } : {}),
      ...(wrapKeySalt ? { wrapKeySalt } : {}),
      ...(storedPayload ? { payload: storedPayload } : {}),
      ...(storedPayloadEnvelope ? { payloadEnvelope: storedPayloadEnvelope } : {}),
      timestamp: data.timestamp,
      schemaVersion: data.schemaVersion,
    };
    await db.put(this.config.v2StoreName, toStore);
  }

  async getKeyMaterialV2(
    profileId: string,
    deviceNumber: number,
    chainId: string,
    keyKind: PasskeyChainKeyKind
  ): Promise<PasskeyChainKeyMaterialV2 | null> {
    const db = await this.getDB();
    const normalizedProfileId = toTrimmedString(profileId || '');
    const normalizedChainId = toTrimmedString(chainId || '').toLowerCase();
    const normalizedKeyKind = toTrimmedString(keyKind || '');
    if (!normalizedProfileId || !normalizedChainId || !normalizedKeyKind) return null;
    const rec = await db.get(this.config.v2StoreName, [normalizedProfileId, deviceNumber, normalizedChainId, normalizedKeyKind]) as PasskeyChainKeyMaterialV2 | undefined;
    if (!rec) return null;
    return hydrateCompatibilityPayloadValue(rec);
  }

  async listKeyMaterialV2ByProfileAndDevice(
    profileId: string,
    deviceNumber: number,
    chainId?: string,
  ): Promise<PasskeyChainKeyMaterialV2[]> {
    const db = await this.getDB();
    const normalizedProfileId = toTrimmedString(profileId || '');
    const normalizedChainId = toTrimmedString(chainId || '').toLowerCase();
    if (!normalizedProfileId) return [];
    if (!Number.isSafeInteger(deviceNumber) || deviceNumber < 1) return [];

    const tx = db.transaction(this.config.v2StoreName, 'readonly');
    const rows = await tx.store
      .index('profileId_deviceNumber')
      .getAll([normalizedProfileId, deviceNumber]) as PasskeyChainKeyMaterialV2[];
    await tx.done;

    const hydratedRows = (rows || [])
      .map((row) => hydrateCompatibilityPayloadValue(row))
      .filter((row): row is PasskeyChainKeyMaterialV2 => !!row);
    if (!normalizedChainId) return hydratedRows;
    return hydratedRows.filter((row) => String(row.chainId).trim().toLowerCase() === normalizedChainId);
  }

  async deleteKeyMaterialV2(
    profileId: string,
    deviceNumber: number,
    chainId: string,
    keyKind: PasskeyChainKeyKind,
  ): Promise<void> {
    const db = await this.getDB();
    const normalizedProfileId = toTrimmedString(profileId || '');
    const normalizedChainId = toTrimmedString(chainId || '').toLowerCase();
    const normalizedKeyKind = toTrimmedString(keyKind || '');
    if (!normalizedProfileId || !normalizedChainId || !normalizedKeyKind) return;
    if (!Number.isSafeInteger(deviceNumber) || deviceNumber < 1) return;
    await db.delete(this.config.v2StoreName, [normalizedProfileId, deviceNumber, normalizedChainId, normalizedKeyKind]);
  }
}
