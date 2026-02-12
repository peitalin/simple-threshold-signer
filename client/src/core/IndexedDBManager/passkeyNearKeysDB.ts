import { openDB, type IDBPDatabase } from 'idb';
import { type ThresholdEd25519ParticipantV1 } from '../../../../shared/src/threshold/participants';

const DB_CONFIG: PasskeyNearKeysDBConfig = {
  dbName: 'PasskeyNearKeys',
  // v7: cutover to V2-only key material store; drop legacy keyMaterial store
  dbVersion: 7,
  v2StoreName: 'keyMaterialV2',
  v2KeyPath: ['profileId', 'deviceNumber', 'chainId', 'keyKind'],
} as const;

export type ClientShareDerivation = 'prf_first_v1';

export type PasskeyNearKeyMaterialKind =
  | 'local_near_sk_v3'
  | 'threshold_ed25519_2p_v1';

export interface BasePasskeyNearKeyMaterial {
  nearAccountId: string;
  deviceNumber: number; // 1-indexed device number
  kind: PasskeyNearKeyMaterialKind;
  /** NEAR ed25519 public key (e.g. `ed25519:...`) */
  publicKey: string;
  /**
   * HKDF salt used alongside WrapKeySeed for KEK derivation.
   *
   * This is required for `local_near_sk_v3` (encrypted key storage) but is not
   * required for threshold-only key material.
   */
  wrapKeySalt?: string;
  timestamp: number;
}

export interface LocalNearSkV3Material extends BasePasskeyNearKeyMaterial {
  kind: 'local_near_sk_v3';
  wrapKeySalt: string;
  encryptedSk: string;
  /**
   * Base64url-encoded AEAD nonce (ChaCha20-Poly1305) for `encryptedSk`.
   */
  chacha20NonceB64u: string;
}

export interface ThresholdEd25519_2p_V1Material extends BasePasskeyNearKeyMaterial {
  kind: 'threshold_ed25519_2p_v1';
  relayerKeyId: string;
  clientShareDerivation: ClientShareDerivation;
  /**
   * Versioned participant list for future n-party support.
   * In 2P, participants are `{id:1, role:'client'}` and `{id:2, role:'relayer', ...}`.
   */
  participants: ThresholdEd25519ParticipantV1[];
}

export type PasskeyNearKeyMaterial =
  | LocalNearSkV3Material
  | ThresholdEd25519_2p_V1Material;

export type PasskeyChainKeyAlgorithm =
  | 'ed25519'
  | 'secp256k1'
  | 'webauthn-p256'
  | string;

export type PasskeyChainKeyKind =
  | 'local_sk_encrypted_v1'
  | 'threshold_share_v1'
  | string;

const KEY_PAYLOAD_ENC_VERSION = 1;
const LOCAL_SK_ENVELOPE_ALG = 'chacha20poly1305-b64u-v1';

export interface PasskeyChainKeyPayloadEnvelopeAAD {
  profileId: string;
  deviceNumber: number;
  chainId: string;
  keyKind: string;
  schemaVersion: number;
  signerId?: string;
  accountAddress?: string;
}

export interface PasskeyChainKeyPayloadEnvelope {
  encVersion: number;
  alg: string;
  nonce: string;
  ciphertext: string;
  tag?: string;
  aad: PasskeyChainKeyPayloadEnvelopeAAD;
}

export interface PasskeyChainKeyMaterialV2 {
  profileId: string;
  deviceNumber: number;
  chainId: string;
  keyKind: PasskeyChainKeyKind;
  algorithm: PasskeyChainKeyAlgorithm;
  publicKey: string;
  signerId?: string;
  wrapKeySalt?: string;
  payload?: Record<string, unknown>;
  payloadEnvelope?: PasskeyChainKeyPayloadEnvelope;
  timestamp: number;
  schemaVersion: number;
}

interface PasskeyNearKeysDBConfig {
  dbName: string;
  dbVersion: number;
  v2StoreName: string;
  v2KeyPath: string | string[];
}

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
        const ensureV2StoreIndexes = (store: any): void => {
          try {
            store.createIndex(
              'profileId_deviceNumber',
              ['profileId', 'deviceNumber'],
              { unique: false }
            );
          } catch {}
          try {
            store.createIndex(
              'chainId_keyKind',
              ['chainId', 'keyKind'],
              { unique: false }
            );
          } catch {}
          try { store.createIndex('publicKey', 'publicKey', { unique: false }); } catch {}
        };

        if (!db.objectStoreNames.contains(DB_CONFIG.v2StoreName)) {
          const v2Store = db.createObjectStore(DB_CONFIG.v2StoreName, { keyPath: DB_CONFIG.v2KeyPath });
          ensureV2StoreIndexes(v2Store);
        } else {
          try {
            const existing = tx.objectStore(DB_CONFIG.v2StoreName);
            ensureV2StoreIndexes(existing);
          } catch {}
        }

        // Stable cutover completed: remove legacy NEAR key store.
        try {
          if (db.objectStoreNames.contains('keyMaterial')) {
            db.deleteObjectStore('keyMaterial');
          }
        } catch {}
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

  private asRecord(value: unknown): Record<string, unknown> | null {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    return value as Record<string, unknown>;
  }

  private sanitizePayload(value: unknown): Record<string, unknown> | undefined {
    const record = this.asRecord(value);
    if (!record) return undefined;
    return { ...record };
  }

  private buildEnvelopeAAD(args: {
    profileId: string;
    deviceNumber: number;
    chainId: string;
    keyKind: string;
    schemaVersion: number;
    signerId?: string;
  }): PasskeyChainKeyPayloadEnvelopeAAD {
    const signerId = String(args.signerId || '').trim();
    return {
      profileId: String(args.profileId || '').trim(),
      deviceNumber: args.deviceNumber,
      chainId: String(args.chainId || '').trim().toLowerCase(),
      keyKind: String(args.keyKind || '').trim(),
      schemaVersion: args.schemaVersion,
      ...(signerId ? { signerId } : {}),
    };
  }

  private normalizeEnvelopeAAD(
    raw: unknown,
    expected: PasskeyChainKeyPayloadEnvelopeAAD,
    context: string,
  ): PasskeyChainKeyPayloadEnvelopeAAD {
    const record = this.asRecord(raw);
    const profileId = String(record?.profileId ?? expected.profileId).trim();
    const chainId = String(record?.chainId ?? expected.chainId).trim().toLowerCase();
    const keyKind = String(record?.keyKind ?? expected.keyKind).trim();
    const schemaVersionRaw = Number(record?.schemaVersion ?? expected.schemaVersion);
    const schemaVersion = Number.isSafeInteger(schemaVersionRaw) && schemaVersionRaw >= 1
      ? schemaVersionRaw
      : expected.schemaVersion;
    const deviceNumberRaw = Number(record?.deviceNumber ?? expected.deviceNumber);
    const deviceNumber = Number.isSafeInteger(deviceNumberRaw) && deviceNumberRaw >= 1
      ? deviceNumberRaw
      : expected.deviceNumber;
    const signerId = String(record?.signerId ?? expected.signerId ?? '').trim();
    const accountAddress = String(record?.accountAddress || '').trim().toLowerCase();
    const normalized: PasskeyChainKeyPayloadEnvelopeAAD = {
      profileId,
      deviceNumber,
      chainId,
      keyKind,
      schemaVersion,
      ...(signerId ? { signerId } : {}),
      ...(accountAddress ? { accountAddress } : {}),
    };

    const matchesExpected =
      normalized.profileId === expected.profileId
      && normalized.deviceNumber === expected.deviceNumber
      && normalized.chainId === expected.chainId
      && normalized.keyKind === expected.keyKind
      && normalized.schemaVersion === expected.schemaVersion
      && (!expected.signerId || normalized.signerId === expected.signerId);
    if (!matchesExpected) {
      throw new Error(
        `PasskeyNearKeysDB: payloadEnvelope.aad mismatch for ${context}`,
      );
    }

    return normalized;
  }

  private normalizePayloadEnvelope(
    raw: unknown,
    expectedAAD: PasskeyChainKeyPayloadEnvelopeAAD,
    context: string,
  ): PasskeyChainKeyPayloadEnvelope | undefined {
    if (raw == null) return undefined;
    const record = this.asRecord(raw);
    if (!record) {
      throw new Error(`PasskeyNearKeysDB: Invalid payloadEnvelope object for ${context}`);
    }
    const encVersionRaw = Number(record.encVersion);
    const encVersion = Number.isSafeInteger(encVersionRaw) && encVersionRaw >= 1
      ? encVersionRaw
      : NaN;
    const alg = String(record.alg || '').trim();
    const nonce = String(record.nonce || '').trim();
    const ciphertext = String(record.ciphertext || '').trim();
    const tag = String(record.tag || '').trim();
    if (!Number.isFinite(encVersion)) {
      throw new Error(`PasskeyNearKeysDB: Invalid payloadEnvelope.encVersion for ${context}`);
    }
    if (!alg || !nonce || !ciphertext) {
      throw new Error(`PasskeyNearKeysDB: Missing payloadEnvelope cryptographic fields for ${context}`);
    }
    return {
      encVersion,
      alg,
      nonce,
      ciphertext,
      ...(tag ? { tag } : {}),
      aad: this.normalizeEnvelopeAAD(record.aad, expectedAAD, context),
    };
  }

  private extractLegacyLocalSkPayload(payload: Record<string, unknown> | undefined): {
    encryptedSk: string;
    chacha20NonceB64u: string;
  } | null {
    if (!payload) return null;
    const encryptedSk = String(payload.encryptedSk || '').trim();
    const chacha20NonceB64u = String(payload.chacha20NonceB64u || '').trim();
    if (!encryptedSk || !chacha20NonceB64u) return null;
    return { encryptedSk, chacha20NonceB64u };
  }

  private removeLegacyLocalSkPayloadFields(payload: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
    if (!payload) return undefined;
    const next = { ...payload };
    delete next.encryptedSk;
    delete next.chacha20NonceB64u;
    return Object.keys(next).length > 0 ? next : undefined;
  }

  private hydrateCompatibilityPayload(rec: PasskeyChainKeyMaterialV2): PasskeyChainKeyMaterialV2 | null {
    const profileId = String(rec.profileId || '').trim();
    const chainId = String(rec.chainId || '').trim().toLowerCase();
    const keyKind = String(rec.keyKind || '').trim();
    const algorithm = String(rec.algorithm || '').trim();
    const publicKey = String(rec.publicKey || '').trim();
    const signerId = String(rec.signerId || '').trim();
    const wrapKeySalt = String(rec.wrapKeySalt || '').trim();
    if (!profileId || !chainId || !keyKind || !algorithm || !publicKey) return null;
    if (!Number.isSafeInteger(rec.deviceNumber) || rec.deviceNumber < 1) return null;
    if (typeof rec.timestamp !== 'number') return null;
    if (!Number.isSafeInteger(rec.schemaVersion) || rec.schemaVersion < 1) return null;

    const payload = this.sanitizePayload(rec.payload);
    const expectedAAD = this.buildEnvelopeAAD({
      profileId,
      deviceNumber: rec.deviceNumber,
      chainId,
      keyKind,
      schemaVersion: rec.schemaVersion,
      ...(signerId ? { signerId } : {}),
    });
    const payloadEnvelope = this.normalizePayloadEnvelope(
      rec.payloadEnvelope,
      expectedAAD,
      `${profileId}/${rec.deviceNumber}/${chainId}/${keyKind}`,
    );

    if (keyKind === 'local_sk_encrypted_v1') {
      const legacyPayload = this.extractLegacyLocalSkPayload(payload);
      const encryptedSkFromEnvelope = String(payloadEnvelope?.ciphertext || '').trim();
      const nonceFromEnvelope = String(payloadEnvelope?.nonce || '').trim();
      const encryptedSk = String(legacyPayload?.encryptedSk || encryptedSkFromEnvelope).trim();
      const chacha20NonceB64u = String(legacyPayload?.chacha20NonceB64u || nonceFromEnvelope).trim();
      if (!encryptedSk || !chacha20NonceB64u) return null;
      if (
        legacyPayload
        && payloadEnvelope
        && (
          legacyPayload.encryptedSk !== encryptedSkFromEnvelope
          || legacyPayload.chacha20NonceB64u !== nonceFromEnvelope
        )
      ) {
        return null;
      }
      return {
        ...rec,
        profileId,
        chainId,
        keyKind,
        algorithm,
        publicKey,
        ...(signerId ? { signerId } : {}),
        ...(wrapKeySalt ? { wrapKeySalt } : {}),
        ...(payloadEnvelope ? { payloadEnvelope } : {}),
        payload: {
          ...(this.removeLegacyLocalSkPayloadFields(payload) || {}),
          encryptedSk,
          chacha20NonceB64u,
        },
      };
    }

    return {
      ...rec,
      profileId,
      chainId,
      keyKind,
      algorithm,
      publicKey,
      ...(signerId ? { signerId } : {}),
      ...(wrapKeySalt ? { wrapKeySalt } : {}),
      ...(payload ? { payload } : {}),
      ...(payloadEnvelope ? { payloadEnvelope } : {}),
    };
  }

  async storeKeyMaterialV2(data: PasskeyChainKeyMaterialV2): Promise<void> {
    const db = await this.getDB();
    const profileId = String(data.profileId || '').trim();
    const signerId = String(data.signerId || '').trim();
    const wrapKeySalt = String(data.wrapKeySalt || '').trim();
    const chainId = String(data.chainId || '').trim().toLowerCase();
    const keyKind = String(data.keyKind || '').trim();
    const algorithm = String(data.algorithm || '').trim();
    const publicKey = String(data.publicKey || '').trim();
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

    const payload = this.sanitizePayload(data.payload);
    const expectedAAD = this.buildEnvelopeAAD({
      profileId,
      deviceNumber: data.deviceNumber,
      chainId,
      keyKind,
      schemaVersion: data.schemaVersion,
      ...(signerId ? { signerId } : {}),
    });
    let payloadEnvelope = this.normalizePayloadEnvelope(
      data.payloadEnvelope,
      expectedAAD,
      `${profileId}/${data.deviceNumber}/${chainId}/${keyKind}`,
    );

    let storedPayload = payload;
    if (keyKind === 'local_sk_encrypted_v1') {
      const legacyPayload = this.extractLegacyLocalSkPayload(payload);
      if (!payloadEnvelope) {
        if (!legacyPayload) {
          throw new Error(
            'PasskeyNearKeysDB: local_sk_encrypted_v1 requires payloadEnvelope or legacy encryptedSk/chacha20NonceB64u payload fields',
          );
        }
        payloadEnvelope = {
          encVersion: KEY_PAYLOAD_ENC_VERSION,
          alg: LOCAL_SK_ENVELOPE_ALG,
          nonce: legacyPayload.chacha20NonceB64u,
          ciphertext: legacyPayload.encryptedSk,
          aad: expectedAAD,
        };
      } else if (
        legacyPayload
        && (
          legacyPayload.encryptedSk !== payloadEnvelope.ciphertext
          || legacyPayload.chacha20NonceB64u !== payloadEnvelope.nonce
        )
      ) {
        throw new Error(
          'PasskeyNearKeysDB: local_sk_encrypted_v1 payload and payloadEnvelope values must match',
        );
      }
      // Do not persist duplicate legacy ciphertext fields at rest.
      storedPayload = this.removeLegacyLocalSkPayloadFields(payload);
    }

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
      ...(payloadEnvelope ? { payloadEnvelope } : {}),
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
    const normalizedProfileId = String(profileId || '').trim();
    const normalizedChainId = String(chainId || '').trim().toLowerCase();
    const normalizedKeyKind = String(keyKind || '').trim();
    if (!normalizedProfileId || !normalizedChainId || !normalizedKeyKind) return null;
    const rec = await db.get(this.config.v2StoreName, [normalizedProfileId, deviceNumber, normalizedChainId, normalizedKeyKind]) as PasskeyChainKeyMaterialV2 | undefined;
    if (!rec) return null;
    return this.hydrateCompatibilityPayload(rec);
  }

  async listKeyMaterialV2ByProfileAndDevice(
    profileId: string,
    deviceNumber: number,
    chainId?: string,
  ): Promise<PasskeyChainKeyMaterialV2[]> {
    const db = await this.getDB();
    const normalizedProfileId = String(profileId || '').trim();
    const normalizedChainId = String(chainId || '').trim().toLowerCase();
    if (!normalizedProfileId) return [];
    if (!Number.isSafeInteger(deviceNumber) || deviceNumber < 1) return [];

    const tx = db.transaction(this.config.v2StoreName, 'readonly');
    const rows = await tx.store
      .index('profileId_deviceNumber')
      .getAll([normalizedProfileId, deviceNumber]) as PasskeyChainKeyMaterialV2[];
    await tx.done;

    const hydratedRows = (rows || [])
      .map((row) => this.hydrateCompatibilityPayload(row))
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
    const normalizedProfileId = String(profileId || '').trim();
    const normalizedChainId = String(chainId || '').trim().toLowerCase();
    const normalizedKeyKind = String(keyKind || '').trim();
    if (!normalizedProfileId || !normalizedChainId || !normalizedKeyKind) return;
    if (!Number.isSafeInteger(deviceNumber) || deviceNumber < 1) return;
    await db.delete(this.config.v2StoreName, [normalizedProfileId, deviceNumber, normalizedChainId, normalizedKeyKind]);
  }
}
