import type { NormalizedLogger } from './logger';
import { isObject as isObjectLoose, toOptionalTrimmedString } from '@shared/utils/validation';
import { getPostgresPool, getPostgresUrlFromConfig } from '../storage/postgres';

export type NearPublicKeyKind = 'threshold' | 'local' | 'backup' | 'ephemeral';

export type NearPublicKeyRecord = {
  version: 'near_public_key_v1';
  userId: string;
  publicKey: string;
  kind: NearPublicKeyKind;
  deviceNumber?: number;
  credentialIdB64u?: string;
  rpId?: string;
  createdAtMs: number;
  updatedAtMs: number;
  addedTxHash?: string;
  removedAtMs?: number;
};

export interface NearPublicKeyStore {
  put(record: NearPublicKeyRecord): Promise<void>;
  listByUserId(userId: string): Promise<NearPublicKeyRecord[]>;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return isObjectLoose(v);
}

function parseNearPublicKeyKind(input: unknown): NearPublicKeyKind | null {
  const k = toOptionalTrimmedString(input);
  if (k === 'threshold' || k === 'local' || k === 'backup' || k === 'ephemeral') return k;
  return null;
}

function parseNearPublicKeyRecord(raw: unknown): NearPublicKeyRecord | null {
  if (!isObject(raw)) return null;
  const version = toOptionalTrimmedString(raw.version);
  if (version !== 'near_public_key_v1') return null;
  const userId = toOptionalTrimmedString(raw.userId);
  const publicKey = toOptionalTrimmedString(raw.publicKey);
  const kind = parseNearPublicKeyKind((raw as any).kind);
  const createdAtMsRaw = (raw as any).createdAtMs;
  const updatedAtMsRaw = (raw as any).updatedAtMs;
  const createdAtMs = typeof createdAtMsRaw === 'number' ? createdAtMsRaw : Number(createdAtMsRaw);
  const updatedAtMs = typeof updatedAtMsRaw === 'number' ? updatedAtMsRaw : Number(updatedAtMsRaw);

  if (!userId || !publicKey || !kind) return null;
  if (!publicKey.startsWith('ed25519:')) return null;
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(updatedAtMs) || updatedAtMs <= 0) return null;

  const deviceNumberRaw = (raw as any).deviceNumber;
  const deviceNumber = typeof deviceNumberRaw === 'number' ? deviceNumberRaw : Number(deviceNumberRaw);
  const credentialIdB64u = toOptionalTrimmedString((raw as any).credentialIdB64u);
  const rpId = toOptionalTrimmedString((raw as any).rpId);
  const addedTxHash = toOptionalTrimmedString((raw as any).addedTxHash);
  const removedAtMsRaw = (raw as any).removedAtMs;
  const removedAtMs = typeof removedAtMsRaw === 'number' ? removedAtMsRaw : Number(removedAtMsRaw);

  return {
    version: 'near_public_key_v1',
    userId,
    publicKey,
    kind,
    ...(Number.isFinite(deviceNumber) && deviceNumber >= 1 ? { deviceNumber: Math.floor(deviceNumber) } : {}),
    ...(credentialIdB64u ? { credentialIdB64u } : {}),
    ...(rpId ? { rpId } : {}),
    createdAtMs: Math.floor(createdAtMs),
    updatedAtMs: Math.floor(updatedAtMs),
    ...(addedTxHash ? { addedTxHash } : {}),
    ...(Number.isFinite(removedAtMs) && removedAtMs > 0 ? { removedAtMs: Math.floor(removedAtMs) } : {}),
  };
}

class InMemoryNearPublicKeyStore implements NearPublicKeyStore {
  private readonly byUser = new Map<string, Map<string, NearPublicKeyRecord>>();

  async put(record: NearPublicKeyRecord): Promise<void> {
    const parsed = parseNearPublicKeyRecord(record);
    if (!parsed) throw new Error('Invalid near public key record');
    const key = parsed.userId;
    const bucket = this.byUser.get(key) || new Map<string, NearPublicKeyRecord>();
    bucket.set(parsed.publicKey, parsed);
    this.byUser.set(key, bucket);
  }

  async listByUserId(userId: string): Promise<NearPublicKeyRecord[]> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) return [];
    const bucket = this.byUser.get(uid);
    if (!bucket) return [];
    const out = Array.from(bucket.values()).map((r) => parseNearPublicKeyRecord(r)).filter(Boolean) as NearPublicKeyRecord[];
    out.sort((a, b) => (a.deviceNumber || 0) - (b.deviceNumber || 0));
    return out;
  }
}

class PostgresNearPublicKeyStore implements NearPublicKeyStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async put(record: NearPublicKeyRecord): Promise<void> {
    const parsed = parseNearPublicKeyRecord(record);
    if (!parsed) throw new Error('Invalid near public key record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO tatchi_near_public_keys (namespace, user_id, public_key, record_json, created_at_ms, updated_at_ms)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (namespace, user_id, public_key)
        DO UPDATE SET
          record_json = EXCLUDED.record_json,
          updated_at_ms = EXCLUDED.updated_at_ms
      `,
      [this.namespace, parsed.userId, parsed.publicKey, parsed, parsed.createdAtMs, parsed.updatedAtMs],
    );
  }

  async listByUserId(userId: string): Promise<NearPublicKeyRecord[]> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) return [];
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json
        FROM tatchi_near_public_keys
        WHERE namespace = $1 AND user_id = $2
      `,
      [this.namespace, uid],
    );
    const out: NearPublicKeyRecord[] = [];
    for (const r of rows || []) {
      const parsed = parseNearPublicKeyRecord((r as any)?.record_json);
      if (parsed) out.push(parsed);
    }
    out.sort((a, b) => (a.deviceNumber || 0) - (b.deviceNumber || 0));
    return out;
  }
}

export function createNearPublicKeyStore(input: {
  config?: Record<string, unknown> | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): NearPublicKeyStore {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const postgresUrl = getPostgresUrlFromConfig(config);
  const namespace = toOptionalTrimmedString(config.NEAR_PUBLIC_KEY_NAMESPACE)
    || toOptionalTrimmedString(config.THRESHOLD_PREFIX)
    || '';

  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error('[near-public-keys] POSTGRES_URL is set but Postgres is not supported in this runtime');
    }
    input.logger.info('[near-public-keys] Using Postgres store for NEAR public key metadata');
    return new PostgresNearPublicKeyStore({ postgresUrl, namespace });
  }

  input.logger.info('[near-public-keys] Using in-memory store for NEAR public key metadata');
  return new InMemoryNearPublicKeyStore();
}

