import type { NormalizedLogger } from '../../logger';
import type { ThresholdEd25519KeyStoreConfigInput } from '../../types';
import { RedisTcpClient, UpstashRedisRestClient, redisGetdelJson, redisSetJson } from '../kv';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { getPostgresPool, getPostgresUrlFromConfig } from '../../../storage/postgres';
import {
  isObject,
  parseThresholdEcdsaPresignSessionRecord,
  parseThresholdEcdsaPresignatureRelayerShareRecord,
  parseThresholdEcdsaSigningSessionRecord,
  toThresholdEcdsaPresignPrefix,
  toThresholdEcdsaPrefixFromBase,
  toThresholdEcdsaSigningPrefix,
} from '../validation';
import { createCloudflareDurableObjectThresholdEcdsaStores } from './CloudflareDurableObjectStore';

export type ThresholdEcdsaSigningSessionRecord = {
  expiresAtMs: number;
  mpcSessionId: string;
  relayerKeyId: string;
  signingDigestB64u: string;
  userId: string;
  rpId: string;
  clientVerifyingShareB64u: string;
  participantIds: number[];
  presignatureId: string;
  entropyB64u: string;
  bigRB64u?: string;
};

export type ThresholdEcdsaPresignatureRelayerShareRecord = {
  relayerKeyId: string;
  presignatureId: string;
  bigRB64u: string;
  /** Base64url-encoded scalar share for k^{-1}. */
  kShareB64u: string;
  /** Base64url-encoded scalar share for x*k^{-1}. */
  sigmaShareB64u: string;
  createdAtMs: number;
};

export type ThresholdEcdsaPresignSessionStage = 'triples' | 'triples_done' | 'presign' | 'done';

export type ThresholdEcdsaPresignSessionRecord = {
  expiresAtMs: number;
  userId: string;
  rpId: string;
  relayerKeyId: string;
  participantIds: number[];
  clientParticipantId: number;
  relayerParticipantId: number;
  stage: ThresholdEcdsaPresignSessionStage;
  version: number;
  wasmSessionStateB64u: string;
  createdAtMs: number;
  updatedAtMs: number;
};

export interface ThresholdEcdsaSigningSessionStore {
  putSigningSession(id: string, record: ThresholdEcdsaSigningSessionRecord, ttlMs: number): Promise<void>;
  takeSigningSession(id: string): Promise<ThresholdEcdsaSigningSessionRecord | null>;
}

export type ThresholdEcdsaPresignSessionCasResult =
  | { ok: true; record: ThresholdEcdsaPresignSessionRecord }
  | { ok: false; code: 'not_found' | 'expired' | 'version_mismatch' };

export interface ThresholdEcdsaPresignSessionStore {
  createSession(id: string, record: ThresholdEcdsaPresignSessionRecord, ttlMs: number): Promise<{ ok: true } | { ok: false; code: 'exists' }>;
  getSession(id: string): Promise<ThresholdEcdsaPresignSessionRecord | null>;
  advanceSessionCas(input: {
    id: string;
    expectedVersion: number;
    nextRecord: ThresholdEcdsaPresignSessionRecord;
    ttlMs: number;
  }): Promise<ThresholdEcdsaPresignSessionCasResult>;
  deleteSession(id: string): Promise<void>;
}

export interface ThresholdEcdsaPresignaturePool {
  reserve(relayerKeyId: string): Promise<ThresholdEcdsaPresignatureRelayerShareRecord | null>;
  consume(relayerKeyId: string, presignatureId: string): Promise<ThresholdEcdsaPresignatureRelayerShareRecord | null>;
  discard(relayerKeyId: string, presignatureId: string): Promise<void>;
  put(record: ThresholdEcdsaPresignatureRelayerShareRecord): Promise<void>;
}

export class InMemoryThresholdEcdsaSigningSessionStore implements ThresholdEcdsaSigningSessionStore {
  private readonly map = new Map<string, { value: ThresholdEcdsaSigningSessionRecord; expiresAtMs: number }>();

  async putSigningSession(id: string, record: ThresholdEcdsaSigningSessionRecord, ttlMs: number): Promise<void> {
    const key = toOptionalTrimmedString(id);
    if (!key) throw new Error('Missing signingSessionId');
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    this.map.set(key, { value: record, expiresAtMs });
  }

  async takeSigningSession(id: string): Promise<ThresholdEcdsaSigningSessionRecord | null> {
    const key = toOptionalTrimmedString(id);
    if (!key) return null;
    const entry = this.map.get(key);
    this.map.delete(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAtMs) return null;
    return entry.value;
  }
}

export class InMemoryThresholdEcdsaPresignSessionStore implements ThresholdEcdsaPresignSessionStore {
  private readonly map = new Map<string, { value: ThresholdEcdsaPresignSessionRecord; expiresAtMs: number }>();

  async createSession(
    id: string,
    record: ThresholdEcdsaPresignSessionRecord,
    ttlMs: number,
  ): Promise<{ ok: true } | { ok: false; code: 'exists' }> {
    const key = toOptionalTrimmedString(id);
    if (!key) throw new Error('Missing presignSessionId');

    const parsed = parseThresholdEcdsaPresignSessionRecord(record);
    if (!parsed) throw new Error('Invalid threshold-ecdsa presign session record');

    const existing = this.map.get(key);
    const nowMs = Date.now();
    if (existing && existing.expiresAtMs > nowMs) {
      return { ok: false, code: 'exists' };
    }

    const expiresAtMs = nowMs + Math.max(0, Number(ttlMs) || 0);
    this.map.set(key, { value: parsed, expiresAtMs });
    return { ok: true };
  }

  async getSession(id: string): Promise<ThresholdEcdsaPresignSessionRecord | null> {
    const key = toOptionalTrimmedString(id);
    if (!key) return null;
    const entry = this.map.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAtMs) {
      this.map.delete(key);
      return null;
    }
    return entry.value;
  }

  async advanceSessionCas(input: {
    id: string;
    expectedVersion: number;
    nextRecord: ThresholdEcdsaPresignSessionRecord;
    ttlMs: number;
  }): Promise<ThresholdEcdsaPresignSessionCasResult> {
    const key = toOptionalTrimmedString(input.id);
    if (!key) return { ok: false, code: 'not_found' };
    const entry = this.map.get(key);
    if (!entry) return { ok: false, code: 'not_found' };

    const nowMs = Date.now();
    if (nowMs > entry.expiresAtMs) {
      this.map.delete(key);
      return { ok: false, code: 'expired' };
    }

    const expectedVersion = Math.floor(Number(input.expectedVersion));
    if (!Number.isFinite(expectedVersion) || expectedVersion < 1) {
      return { ok: false, code: 'version_mismatch' };
    }
    if (entry.value.version !== expectedVersion) {
      return { ok: false, code: 'version_mismatch' };
    }

    const parsed = parseThresholdEcdsaPresignSessionRecord(input.nextRecord);
    if (!parsed) throw new Error('Invalid threshold-ecdsa presign session record');
    const expiresAtMs = nowMs + Math.max(0, Number(input.ttlMs) || 0);
    this.map.set(key, { value: parsed, expiresAtMs });
    return { ok: true, record: parsed };
  }

  async deleteSession(id: string): Promise<void> {
    const key = toOptionalTrimmedString(id);
    if (!key) return;
    this.map.delete(key);
  }
}

export class InMemoryThresholdEcdsaPresignaturePool implements ThresholdEcdsaPresignaturePool {
  private readonly availableByKey = new Map<string, ThresholdEcdsaPresignatureRelayerShareRecord[]>();
  private readonly reservedByKey = new Map<string, Map<string, { value: ThresholdEcdsaPresignatureRelayerShareRecord; expiresAtMs: number }>>();
  private readonly reservationTtlMs: number;

  constructor(input?: { reservationTtlMs?: number }) {
    this.reservationTtlMs = Math.max(1, Math.floor(Number(input?.reservationTtlMs) || 120_000));
  }

  private gc(relayerKeyId: string): void {
    const reserved = this.reservedByKey.get(relayerKeyId);
    if (!reserved) return;
    const now = Date.now();
    for (const [id, entry] of reserved.entries()) {
      if (now > entry.expiresAtMs) reserved.delete(id);
    }
    if (reserved.size === 0) this.reservedByKey.delete(relayerKeyId);
  }

  async put(record: ThresholdEcdsaPresignatureRelayerShareRecord): Promise<void> {
    const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
    const presignatureId = toOptionalTrimmedString(record.presignatureId);
    if (!relayerKeyId || !presignatureId) throw new Error('Missing relayerKeyId/presignatureId');

    const list = this.availableByKey.get(relayerKeyId) || [];
    list.push(record);
    this.availableByKey.set(relayerKeyId, list);
  }

  async reserve(relayerKeyId: string): Promise<ThresholdEcdsaPresignatureRelayerShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    if (!key) return null;
    this.gc(key);
    const list = this.availableByKey.get(key);
    if (!list || list.length === 0) return null;
    const record = list.shift()!;
    this.availableByKey.set(key, list);

    let reserved = this.reservedByKey.get(key);
    if (!reserved) {
      reserved = new Map();
      this.reservedByKey.set(key, reserved);
    }
    reserved.set(record.presignatureId, { value: record, expiresAtMs: Date.now() + this.reservationTtlMs });
    return record;
  }

  async consume(relayerKeyId: string, presignatureId: string): Promise<ThresholdEcdsaPresignatureRelayerShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return null;
    this.gc(key);
    const reserved = this.reservedByKey.get(key);
    if (!reserved) return null;
    const entry = reserved.get(id) || null;
    reserved.delete(id);
    if (reserved.size === 0) this.reservedByKey.delete(key);
    return entry?.value || null;
  }

  async discard(relayerKeyId: string, presignatureId: string): Promise<void> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return;
    this.gc(key);
    const reserved = this.reservedByKey.get(key);
    reserved?.delete(id);
    if (reserved && reserved.size === 0) this.reservedByKey.delete(key);
  }
}

class UpstashRedisRestThresholdEcdsaSigningSessionStore implements ThresholdEcdsaSigningSessionStore {
  private readonly client: UpstashRedisRestClient;
  private readonly keyPrefix: string;

  constructor(input: { url: string; token: string; keyPrefix: string }) {
    this.client = new UpstashRedisRestClient({ url: input.url, token: input.token });
    this.keyPrefix = input.keyPrefix;
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  async putSigningSession(id: string, record: ThresholdEcdsaSigningSessionRecord, ttlMs: number): Promise<void> {
    const key = toOptionalTrimmedString(id);
    if (!key) throw new Error('Missing signingSessionId');
    await this.client.setJson(this.key(key), record, Math.max(0, Number(ttlMs) || 0));
  }

  async takeSigningSession(id: string): Promise<ThresholdEcdsaSigningSessionRecord | null> {
    const key = toOptionalTrimmedString(id);
    if (!key) return null;
    const raw = await this.client.getdelJson(this.key(key));
    return (parseThresholdEcdsaSigningSessionRecord(raw) as ThresholdEcdsaSigningSessionRecord | null);
  }
}

class RedisTcpThresholdEcdsaSigningSessionStore implements ThresholdEcdsaSigningSessionStore {
  private readonly client: RedisTcpClient;
  private readonly keyPrefix: string;

  constructor(input: { redisUrl: string; keyPrefix: string }) {
    const url = toOptionalTrimmedString(input.redisUrl);
    if (!url) throw new Error('redis-tcp signing session store missing redisUrl');
    this.client = new RedisTcpClient(url);
    this.keyPrefix = input.keyPrefix;
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  async putSigningSession(id: string, record: ThresholdEcdsaSigningSessionRecord, ttlMs: number): Promise<void> {
    const key = toOptionalTrimmedString(id);
    if (!key) throw new Error('Missing signingSessionId');
    await redisSetJson(this.client, this.key(key), record, Math.max(0, Number(ttlMs) || 0));
  }

  async takeSigningSession(id: string): Promise<ThresholdEcdsaSigningSessionRecord | null> {
    const key = toOptionalTrimmedString(id);
    if (!key) return null;
    const raw = await redisGetdelJson(this.client, this.key(key));
    return (parseThresholdEcdsaSigningSessionRecord(raw) as ThresholdEcdsaSigningSessionRecord | null);
  }
}

class UpstashRedisRestThresholdEcdsaPresignSessionStore implements ThresholdEcdsaPresignSessionStore {
  private readonly client: UpstashRedisRestClient;
  private readonly keyPrefix: string;

  constructor(input: { url: string; token: string; keyPrefix: string }) {
    this.client = new UpstashRedisRestClient({ url: input.url, token: input.token });
    this.keyPrefix = input.keyPrefix;
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  async createSession(
    id: string,
    record: ThresholdEcdsaPresignSessionRecord,
    ttlMs: number,
  ): Promise<{ ok: true } | { ok: false; code: 'exists' }> {
    const key = toOptionalTrimmedString(id);
    if (!key) throw new Error('Missing presignSessionId');
    const parsed = parseThresholdEcdsaPresignSessionRecord(record);
    if (!parsed) throw new Error('Invalid threshold-ecdsa presign session record');
    try {
      const raw = await this.client.eval(
        ECDSA_PRESIGN_SESSION_CREATE_LUA,
        [this.key(key)],
        [
          JSON.stringify(parsed),
          String(toRedisMilliseconds(ttlMs)),
          String(Date.now()),
        ],
      );
      if (raw === 'ok') return { ok: true };
      if (raw === 'exists') return { ok: false, code: 'exists' };
      throw new Error(`[threshold-ecdsa] Unexpected Upstash CAS-create result: ${String(raw)}`);
    } catch (e: unknown) {
      const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || '');
      if (isEvalUnsupportedError(msg)) {
        throw new Error('[threshold-ecdsa] Upstash EVAL is required for atomic presign-session CAS; ensure scripting is enabled');
      }
      throw e;
    }
  }

  async getSession(id: string): Promise<ThresholdEcdsaPresignSessionRecord | null> {
    const key = toOptionalTrimmedString(id);
    if (!key) return null;
    const record = parsePresignSessionRecordFromRaw(await this.client.getJson(this.key(key)));
    if (!record) return null;
    if (Date.now() > record.expiresAtMs) {
      await this.client.del(this.key(key));
      return null;
    }
    return record;
  }

  async advanceSessionCas(input: {
    id: string;
    expectedVersion: number;
    nextRecord: ThresholdEcdsaPresignSessionRecord;
    ttlMs: number;
  }): Promise<ThresholdEcdsaPresignSessionCasResult> {
    const key = toOptionalTrimmedString(input.id);
    if (!key) return { ok: false, code: 'not_found' };
    const expectedVersion = Math.floor(Number(input.expectedVersion));
    if (!Number.isFinite(expectedVersion) || expectedVersion < 1) return { ok: false, code: 'version_mismatch' };
    const parsed = parseThresholdEcdsaPresignSessionRecord(input.nextRecord);
    if (!parsed) throw new Error('Invalid threshold-ecdsa presign session record');
    try {
      const raw = await this.client.eval(
        ECDSA_PRESIGN_SESSION_CAS_LUA,
        [this.key(key)],
        [
          String(expectedVersion),
          JSON.stringify(parsed),
          String(toRedisMilliseconds(input.ttlMs)),
          String(Date.now()),
        ],
      );
      return parsePresignSessionCasLuaResult(raw);
    } catch (e: unknown) {
      const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || '');
      if (isEvalUnsupportedError(msg)) {
        throw new Error('[threshold-ecdsa] Upstash EVAL is required for atomic presign-session CAS; ensure scripting is enabled');
      }
      throw e;
    }
  }

  async deleteSession(id: string): Promise<void> {
    const key = toOptionalTrimmedString(id);
    if (!key) return;
    await this.client.del(this.key(key));
  }
}

class RedisTcpThresholdEcdsaPresignSessionStore implements ThresholdEcdsaPresignSessionStore {
  private readonly client: RedisTcpClient;
  private readonly keyPrefix: string;

  constructor(input: { redisUrl: string; keyPrefix: string }) {
    const url = toOptionalTrimmedString(input.redisUrl);
    if (!url) throw new Error('redis-tcp presign session store missing redisUrl');
    this.client = new RedisTcpClient(url);
    this.keyPrefix = input.keyPrefix;
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  async createSession(
    id: string,
    record: ThresholdEcdsaPresignSessionRecord,
    ttlMs: number,
  ): Promise<{ ok: true } | { ok: false; code: 'exists' }> {
    const key = toOptionalTrimmedString(id);
    if (!key) throw new Error('Missing presignSessionId');
    const parsed = parseThresholdEcdsaPresignSessionRecord(record);
    if (!parsed) throw new Error('Invalid threshold-ecdsa presign session record');
    const evalResp = await this.client.send([
      'EVAL',
      ECDSA_PRESIGN_SESSION_CREATE_LUA,
      '1',
      this.key(key),
      JSON.stringify(parsed),
      String(toRedisMilliseconds(ttlMs)),
      String(Date.now()),
    ]);
    if (evalResp.type === 'bulk' || evalResp.type === 'simple') {
      const raw = evalResp.value;
      if (raw === 'ok') return { ok: true };
      if (raw === 'exists') return { ok: false, code: 'exists' };
      throw new Error(`[threshold-ecdsa] Unexpected redis CAS-create result: ${String(raw)}`);
    }
    if (evalResp.type === 'error') {
      if (isEvalUnsupportedError(evalResp.value)) {
        throw new Error('[threshold-ecdsa] Redis EVAL is required for atomic presign-session CAS; enable scripting permissions');
      }
      throw new Error(`Redis EVAL error: ${evalResp.value}`);
    }
    throw new Error(`[threshold-ecdsa] Redis EVAL returned unexpected response type: ${evalResp.type}`);
  }

  async getSession(id: string): Promise<ThresholdEcdsaPresignSessionRecord | null> {
    const key = toOptionalTrimmedString(id);
    if (!key) return null;
    const raw = await this.client.send(['GET', this.key(key)]);
    if (raw.type === 'error') throw new Error(`Redis GET error: ${raw.value}`);
    if (raw.type !== 'bulk' || raw.value === null) return null;
    const record = parsePresignSessionRecordFromRaw(raw.value);
    if (!record) return null;
    if (Date.now() > record.expiresAtMs) {
      await this.deleteSession(key);
      return null;
    }
    return record;
  }

  async advanceSessionCas(input: {
    id: string;
    expectedVersion: number;
    nextRecord: ThresholdEcdsaPresignSessionRecord;
    ttlMs: number;
  }): Promise<ThresholdEcdsaPresignSessionCasResult> {
    const key = toOptionalTrimmedString(input.id);
    if (!key) return { ok: false, code: 'not_found' };
    const expectedVersion = Math.floor(Number(input.expectedVersion));
    if (!Number.isFinite(expectedVersion) || expectedVersion < 1) return { ok: false, code: 'version_mismatch' };
    const parsed = parseThresholdEcdsaPresignSessionRecord(input.nextRecord);
    if (!parsed) throw new Error('Invalid threshold-ecdsa presign session record');
    const evalResp = await this.client.send([
      'EVAL',
      ECDSA_PRESIGN_SESSION_CAS_LUA,
      '1',
      this.key(key),
      String(expectedVersion),
      JSON.stringify(parsed),
      String(toRedisMilliseconds(input.ttlMs)),
      String(Date.now()),
    ]);
    if (evalResp.type === 'bulk' || evalResp.type === 'simple') {
      return parsePresignSessionCasLuaResult(evalResp.value);
    }
    if (evalResp.type === 'error') {
      if (isEvalUnsupportedError(evalResp.value)) {
        throw new Error('[threshold-ecdsa] Redis EVAL is required for atomic presign-session CAS; enable scripting permissions');
      }
      throw new Error(`Redis EVAL error: ${evalResp.value}`);
    }
    throw new Error(`[threshold-ecdsa] Redis EVAL returned unexpected response type: ${evalResp.type}`);
  }

  async deleteSession(id: string): Promise<void> {
    const key = toOptionalTrimmedString(id);
    if (!key) return;
    const resp = await this.client.send(['DEL', this.key(key)]);
    if (resp.type === 'error') throw new Error(`Redis DEL error: ${resp.value}`);
  }
}

class PostgresThresholdEcdsaSigningSessionStore implements ThresholdEcdsaSigningSessionStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async putSigningSession(id: string, record: ThresholdEcdsaSigningSessionRecord, ttlMs: number): Promise<void> {
    const key = toOptionalTrimmedString(id);
    if (!key) throw new Error('Missing signingSessionId');
    const ttl = Math.max(0, Number(ttlMs) || 0);
    const expiresAtMs = Date.now() + ttl;
    const parsed = parseThresholdEcdsaSigningSessionRecord(record);
    if (!parsed) throw new Error('Invalid threshold-ecdsa signing session record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO threshold_ecdsa_signing_sessions (namespace, signing_session_id, record_json, expires_at_ms)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (namespace, signing_session_id)
        DO UPDATE SET record_json = EXCLUDED.record_json, expires_at_ms = EXCLUDED.expires_at_ms
      `,
      [this.namespace, key, parsed, expiresAtMs],
    );
  }

  async takeSigningSession(id: string): Promise<ThresholdEcdsaSigningSessionRecord | null> {
    const key = toOptionalTrimmedString(id);
    if (!key) return null;
    const pool = await this.poolPromise;
    const nowMs = Date.now();
    const { rows } = await pool.query(
      `
        DELETE FROM threshold_ecdsa_signing_sessions
        WHERE namespace = $1 AND signing_session_id = $2
        RETURNING record_json, expires_at_ms
      `,
      [this.namespace, key],
    );
    const row = rows[0] as { record_json?: unknown; expires_at_ms?: unknown } | undefined;
    const expiresAtMs = typeof row?.expires_at_ms === 'number' ? row.expires_at_ms : Number(row?.expires_at_ms);
    if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) return null;
    return (parseThresholdEcdsaSigningSessionRecord(row?.record_json) as ThresholdEcdsaSigningSessionRecord | null);
  }
}

class PostgresThresholdEcdsaPresignSessionStore implements ThresholdEcdsaPresignSessionStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async createSession(
    id: string,
    record: ThresholdEcdsaPresignSessionRecord,
    ttlMs: number,
  ): Promise<{ ok: true } | { ok: false; code: 'exists' }> {
    const key = toOptionalTrimmedString(id);
    if (!key) throw new Error('Missing presignSessionId');
    const parsed = parseThresholdEcdsaPresignSessionRecord(record);
    if (!parsed) throw new Error('Invalid threshold-ecdsa presign session record');
    const ttl = Math.max(0, Number(ttlMs) || 0);
    const expiresAtMs = Date.now() + ttl;
    const pool = await this.poolPromise;
    const result = await pool.query(
      `
        INSERT INTO threshold_ecdsa_presign_sessions (
          namespace,
          presign_session_id,
          record_json,
          stage,
          version,
          expires_at_ms,
          updated_at_ms
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (namespace, presign_session_id) DO NOTHING
        RETURNING presign_session_id
      `,
      [
        this.namespace,
        key,
        parsed,
        parsed.stage,
        parsed.version,
        expiresAtMs,
        Date.now(),
      ],
    );
    if (Array.isArray(result.rows) && result.rows.length > 0) {
      return { ok: true };
    }
    return { ok: false, code: 'exists' };
  }

  async getSession(id: string): Promise<ThresholdEcdsaPresignSessionRecord | null> {
    const key = toOptionalTrimmedString(id);
    if (!key) return null;
    const nowMs = Date.now();
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json, expires_at_ms
        FROM threshold_ecdsa_presign_sessions
        WHERE namespace = $1 AND presign_session_id = $2
      `,
      [this.namespace, key],
    );
    const row = rows[0] as { record_json?: unknown; expires_at_ms?: unknown } | undefined;
    if (!row) return null;
    const expiresAtMs =
      typeof row.expires_at_ms === 'number' ? row.expires_at_ms : Number(row.expires_at_ms);
    if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) return null;
    return (
      parseThresholdEcdsaPresignSessionRecord(row.record_json) as
        | ThresholdEcdsaPresignSessionRecord
        | null
    );
  }

  async advanceSessionCas(input: {
    id: string;
    expectedVersion: number;
    nextRecord: ThresholdEcdsaPresignSessionRecord;
    ttlMs: number;
  }): Promise<ThresholdEcdsaPresignSessionCasResult> {
    const key = toOptionalTrimmedString(input.id);
    if (!key) return { ok: false, code: 'not_found' };
    const expectedVersion = Math.floor(Number(input.expectedVersion));
    if (!Number.isFinite(expectedVersion) || expectedVersion < 1) {
      return { ok: false, code: 'version_mismatch' };
    }
    const parsed = parseThresholdEcdsaPresignSessionRecord(input.nextRecord);
    if (!parsed) throw new Error('Invalid threshold-ecdsa presign session record');

    const ttl = Math.max(0, Number(input.ttlMs) || 0);
    const nowMs = Date.now();
    const expiresAtMs = nowMs + ttl;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        UPDATE threshold_ecdsa_presign_sessions
        SET
          record_json = $4,
          stage = $5,
          version = $6,
          expires_at_ms = $7,
          updated_at_ms = $8
        WHERE namespace = $1
          AND presign_session_id = $2
          AND version = $3
          AND expires_at_ms > $8
        RETURNING record_json
      `,
      [
        this.namespace,
        key,
        expectedVersion,
        parsed,
        parsed.stage,
        parsed.version,
        expiresAtMs,
        nowMs,
      ],
    );
    const row = rows[0] as { record_json?: unknown } | undefined;
    if (row) {
      const updated = parseThresholdEcdsaPresignSessionRecord(row.record_json) as
        | ThresholdEcdsaPresignSessionRecord
        | null;
      if (!updated) throw new Error('Invalid threshold-ecdsa presign session record after CAS');
      return { ok: true, record: updated };
    }

    const existing = await pool.query(
      `
        SELECT version, expires_at_ms
        FROM threshold_ecdsa_presign_sessions
        WHERE namespace = $1 AND presign_session_id = $2
      `,
      [this.namespace, key],
    );
    const existingRow = existing.rows[0] as { version?: unknown; expires_at_ms?: unknown } | undefined;
    if (!existingRow) return { ok: false, code: 'not_found' };
    const existingExpiresAtMs =
      typeof existingRow.expires_at_ms === 'number'
        ? existingRow.expires_at_ms
        : Number(existingRow.expires_at_ms);
    if (!Number.isFinite(existingExpiresAtMs) || existingExpiresAtMs <= nowMs) {
      return { ok: false, code: 'expired' };
    }
    return { ok: false, code: 'version_mismatch' };
  }

  async deleteSession(id: string): Promise<void> {
    const key = toOptionalTrimmedString(id);
    if (!key) return;
    const pool = await this.poolPromise;
    await pool.query(
      `
        DELETE FROM threshold_ecdsa_presign_sessions
        WHERE namespace = $1 AND presign_session_id = $2
      `,
      [this.namespace, key],
    );
  }
}

function parseJson(raw: string): unknown | null {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

const ECDSA_PRESIGN_RESERVE_LUA = `
local listKey = KEYS[1]
local reservedKeyPrefix = KEYS[2]
local ttlSeconds = tonumber(ARGV[1]) or 120
local maxAttempts = tonumber(ARGV[2]) or 8

for _ = 1, maxAttempts do
  local item = redis.call('LPOP', listKey)
  if not item then
    return nil
  end
  local ok, decoded = pcall(cjson.decode, item)
  if ok and type(decoded) == 'table' then
    local presignatureId = decoded['presignatureId']
    if type(presignatureId) == 'string' and presignatureId ~= '' then
      redis.call('SET', reservedKeyPrefix .. presignatureId, item, 'EX', ttlSeconds)
      return item
    end
  end
end

return nil
`.trim();

const ECDSA_PRESIGN_SESSION_CREATE_LUA = `
local key = KEYS[1]
local value = ARGV[1]
local ttlMs = tonumber(ARGV[2]) or 0
local nowMs = tonumber(ARGV[3]) or 0

local existing = redis.call('GET', key)
if existing then
  local ok, decoded = pcall(cjson.decode, existing)
  if ok and type(decoded) == 'table' then
    local expiresAtMs = tonumber(decoded['expiresAtMs']) or 0
    if expiresAtMs > nowMs then
      return 'exists'
    end
  else
    return 'exists'
  end
end

if ttlMs > 0 then
  redis.call('SET', key, value, 'PX', ttlMs)
else
  redis.call('SET', key, value)
end
return 'ok'
`.trim();

const ECDSA_PRESIGN_SESSION_CAS_LUA = `
local key = KEYS[1]
local expectedVersion = tonumber(ARGV[1]) or -1
local nextValue = ARGV[2]
local ttlMs = tonumber(ARGV[3]) or 0
local nowMs = tonumber(ARGV[4]) or 0

local raw = redis.call('GET', key)
if not raw then
  return '__err__:not_found'
end

local ok, decoded = pcall(cjson.decode, raw)
if (not ok) or type(decoded) ~= 'table' then
  return '__err__:not_found'
end

local expiresAtMs = tonumber(decoded['expiresAtMs']) or 0
if expiresAtMs <= nowMs then
  redis.call('DEL', key)
  return '__err__:expired'
end

local version = tonumber(decoded['version']) or -1
if version ~= expectedVersion then
  return '__err__:version_mismatch'
end

if ttlMs > 0 then
  redis.call('SET', key, nextValue, 'PX', ttlMs)
else
  redis.call('SET', key, nextValue)
end

return nextValue
`.trim();

function toRedisSeconds(ms: number): number {
  return Math.max(1, Math.ceil(Math.max(0, Number(ms) || 0) / 1000));
}

function toRedisMilliseconds(ms: number): number {
  return Math.max(1, Math.ceil(Math.max(0, Number(ms) || 0)));
}

function parsePresignatureRecordFromRaw(raw: unknown): ThresholdEcdsaPresignatureRelayerShareRecord | null {
  if (raw === null || raw === undefined) return null;
  if (typeof raw === 'string') {
    return (parseThresholdEcdsaPresignatureRelayerShareRecord(parseJson(raw)) as ThresholdEcdsaPresignatureRelayerShareRecord | null);
  }
  return (parseThresholdEcdsaPresignatureRelayerShareRecord(raw) as ThresholdEcdsaPresignatureRelayerShareRecord | null);
}

function parsePresignSessionRecordFromRaw(raw: unknown): ThresholdEcdsaPresignSessionRecord | null {
  if (raw === null || raw === undefined) return null;
  if (typeof raw === 'string') {
    return (parseThresholdEcdsaPresignSessionRecord(parseJson(raw)) as ThresholdEcdsaPresignSessionRecord | null);
  }
  return (parseThresholdEcdsaPresignSessionRecord(raw) as ThresholdEcdsaPresignSessionRecord | null);
}

function parsePresignSessionCasLuaResult(raw: unknown): ThresholdEcdsaPresignSessionCasResult {
  if (typeof raw === 'string' && raw.startsWith('__err__:')) {
    const codeRaw = raw.slice('__err__:'.length).trim();
    const code = codeRaw === 'expired'
      ? 'expired'
      : codeRaw === 'version_mismatch'
        ? 'version_mismatch'
        : 'not_found';
    return { ok: false, code };
  }
  const record = parsePresignSessionRecordFromRaw(raw);
  if (!record) return { ok: false, code: 'not_found' };
  return { ok: true, record };
}

function isEvalUnsupportedError(message: string): boolean {
  const m = String(message || '').toLowerCase();
  if (!m) return false;
  return m.includes('unknown command')
    || m.includes('err unknown command')
    || m.includes('noperm')
    || m.includes('command is not allowed');
}

class UpstashRedisRestThresholdEcdsaPresignaturePool implements ThresholdEcdsaPresignaturePool {
  private readonly client: UpstashRedisRestClient;
  private readonly keyPrefix: string;
  private readonly reservationTtlMs: number;

  constructor(input: { url: string; token: string; keyPrefix: string; reservationTtlMs?: number }) {
    this.client = new UpstashRedisRestClient({ url: input.url, token: input.token });
    this.keyPrefix = input.keyPrefix;
    this.reservationTtlMs = Math.max(1, Math.floor(Number(input.reservationTtlMs) || 120_000));
  }

  private availKey(relayerKeyId: string): string {
    return `${this.keyPrefix}avail:${relayerKeyId}`;
  }

  private reservedKey(relayerKeyId: string, presignatureId: string): string {
    return `${this.keyPrefix}res:${relayerKeyId}:${presignatureId}`;
  }

  private reservedKeyPrefix(relayerKeyId: string): string {
    return `${this.keyPrefix}res:${relayerKeyId}:`;
  }

  async put(record: ThresholdEcdsaPresignatureRelayerShareRecord): Promise<void> {
    const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
    const presignatureId = toOptionalTrimmedString(record.presignatureId);
    if (!relayerKeyId || !presignatureId) throw new Error('Missing relayerKeyId/presignatureId');
    await this.client.rpush(this.availKey(relayerKeyId), JSON.stringify(record));
  }

  async reserve(relayerKeyId: string): Promise<ThresholdEcdsaPresignatureRelayerShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    if (!key) return null;
    const ttlSeconds = String(toRedisSeconds(this.reservationTtlMs));
    try {
      const raw = await this.client.eval(
        ECDSA_PRESIGN_RESERVE_LUA,
        [this.availKey(key), this.reservedKeyPrefix(key)],
        [ttlSeconds, '8'],
      );
      return parsePresignatureRecordFromRaw(raw);
    } catch (e: unknown) {
      const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || '');
      if (isEvalUnsupportedError(msg)) {
        throw new Error('[threshold-ecdsa] Upstash EVAL is required for atomic presignature reserve; ensure scripting is enabled');
      }
      throw e;
    }
  }

  async consume(relayerKeyId: string, presignatureId: string): Promise<ThresholdEcdsaPresignatureRelayerShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return null;
    const raw = await this.client.getdelJson(this.reservedKey(key, id));
    return (parseThresholdEcdsaPresignatureRelayerShareRecord(raw) as ThresholdEcdsaPresignatureRelayerShareRecord | null);
  }

  async discard(relayerKeyId: string, presignatureId: string): Promise<void> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return;
    await this.client.del(this.reservedKey(key, id));
  }
}

async function redisRpushRaw(client: RedisTcpClient, key: string, value: string): Promise<void> {
  const resp = await client.send(['RPUSH', key, value]);
  if (resp.type === 'error') throw new Error(`Redis RPUSH error: ${resp.value}`);
}

class RedisTcpThresholdEcdsaPresignaturePool implements ThresholdEcdsaPresignaturePool {
  private readonly client: RedisTcpClient;
  private readonly keyPrefix: string;
  private readonly reservationTtlMs: number;

  constructor(input: { redisUrl: string; keyPrefix: string; reservationTtlMs?: number }) {
    const url = toOptionalTrimmedString(input.redisUrl);
    if (!url) throw new Error('redis-tcp presignature pool missing redisUrl');
    this.client = new RedisTcpClient(url);
    this.keyPrefix = input.keyPrefix;
    this.reservationTtlMs = Math.max(1, Math.floor(Number(input.reservationTtlMs) || 120_000));
  }

  private availKey(relayerKeyId: string): string {
    return `${this.keyPrefix}avail:${relayerKeyId}`;
  }

  private reservedKey(relayerKeyId: string, presignatureId: string): string {
    return `${this.keyPrefix}res:${relayerKeyId}:${presignatureId}`;
  }

  private reservedKeyPrefix(relayerKeyId: string): string {
    return `${this.keyPrefix}res:${relayerKeyId}:`;
  }

  async put(record: ThresholdEcdsaPresignatureRelayerShareRecord): Promise<void> {
    const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
    const presignatureId = toOptionalTrimmedString(record.presignatureId);
    if (!relayerKeyId || !presignatureId) throw new Error('Missing relayerKeyId/presignatureId');
    await redisRpushRaw(this.client, this.availKey(relayerKeyId), JSON.stringify(record));
  }

  async reserve(relayerKeyId: string): Promise<ThresholdEcdsaPresignatureRelayerShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    if (!key) return null;
    const ttlSeconds = String(toRedisSeconds(this.reservationTtlMs));
    const evalResp = await this.client.send([
      'EVAL',
      ECDSA_PRESIGN_RESERVE_LUA,
      '2',
      this.availKey(key),
      this.reservedKeyPrefix(key),
      ttlSeconds,
      '8',
    ]);
    if (evalResp.type === 'bulk') {
      return parsePresignatureRecordFromRaw(evalResp.value);
    }
    if (evalResp.type === 'error') {
      if (isEvalUnsupportedError(evalResp.value)) {
        throw new Error('[threshold-ecdsa] Redis EVAL is required for atomic presignature reserve; enable scripting permissions');
      }
      throw new Error(`Redis EVAL error: ${evalResp.value}`);
    }
    throw new Error(`[threshold-ecdsa] Redis EVAL returned unexpected response type: ${evalResp.type}`);
  }

  async consume(relayerKeyId: string, presignatureId: string): Promise<ThresholdEcdsaPresignatureRelayerShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return null;
    const raw = await redisGetdelJson(this.client, this.reservedKey(key, id));
    return (parseThresholdEcdsaPresignatureRelayerShareRecord(raw) as ThresholdEcdsaPresignatureRelayerShareRecord | null);
  }

  async discard(relayerKeyId: string, presignatureId: string): Promise<void> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return;
    const resp = await this.client.send(['DEL', this.reservedKey(key, id)]);
    if (resp.type === 'error') throw new Error(`Redis DEL error: ${resp.value}`);
  }
}

class PostgresThresholdEcdsaPresignaturePool implements ThresholdEcdsaPresignaturePool {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;
  private readonly reservationTtlMs: number;

  constructor(input: { postgresUrl: string; namespace: string; reservationTtlMs?: number }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
    this.reservationTtlMs = Math.max(1, Math.floor(Number(input.reservationTtlMs) || 120_000));
  }

  async put(record: ThresholdEcdsaPresignatureRelayerShareRecord): Promise<void> {
    const parsed = parseThresholdEcdsaPresignatureRelayerShareRecord(record);
    if (!parsed) throw new Error('Invalid threshold-ecdsa presignature record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO threshold_ecdsa_presignatures (
          namespace,
          relayer_key_id,
          presignature_id,
          state,
          record_json,
          created_at_ms
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (namespace, relayer_key_id, presignature_id) DO NOTHING
      `,
      [this.namespace, parsed.relayerKeyId, parsed.presignatureId, 'available', parsed, parsed.createdAtMs],
    );
  }

  async reserve(relayerKeyId: string): Promise<ThresholdEcdsaPresignatureRelayerShareRecord | null> {
    const relayer = toOptionalTrimmedString(relayerKeyId);
    if (!relayer) return null;
    const pool = await this.poolPromise;
    const nowMs = Date.now();
    const reserveExpiresAtMs = nowMs + this.reservationTtlMs;
    const { rows } = await pool.query(
      `
        WITH expired AS (
          DELETE FROM threshold_ecdsa_presignatures
          WHERE namespace = $1 AND relayer_key_id = $2 AND state = 'reserved' AND reserve_expires_at_ms < $3
        ),
        picked AS (
          SELECT presignature_id
          FROM threshold_ecdsa_presignatures
          WHERE namespace = $1 AND relayer_key_id = $2 AND state = 'available'
          ORDER BY created_at_ms ASC
          LIMIT 1
          FOR UPDATE SKIP LOCKED
        )
        UPDATE threshold_ecdsa_presignatures p
        SET state = 'reserved', reserved_at_ms = $3, reserve_expires_at_ms = $4
        FROM picked
        WHERE p.namespace = $1 AND p.relayer_key_id = $2 AND p.presignature_id = picked.presignature_id
        RETURNING p.record_json
      `,
      [this.namespace, relayer, nowMs, reserveExpiresAtMs],
    );
    const record = rows[0]?.record_json;
    return (parseThresholdEcdsaPresignatureRelayerShareRecord(record) as ThresholdEcdsaPresignatureRelayerShareRecord | null);
  }

  async consume(relayerKeyId: string, presignatureId: string): Promise<ThresholdEcdsaPresignatureRelayerShareRecord | null> {
    const relayer = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!relayer || !id) return null;
    const pool = await this.poolPromise;
    const nowMs = Date.now();
    const { rows } = await pool.query(
      `
        DELETE FROM threshold_ecdsa_presignatures
        WHERE namespace = $1 AND relayer_key_id = $2 AND presignature_id = $3 AND state = 'reserved'
        RETURNING record_json, reserve_expires_at_ms
      `,
      [this.namespace, relayer, id],
    );
    const row = rows[0] as { record_json?: unknown; reserve_expires_at_ms?: unknown } | undefined;
    const reserveExpiresAtMs = typeof row?.reserve_expires_at_ms === 'number'
      ? row.reserve_expires_at_ms
      : Number(row?.reserve_expires_at_ms);
    if (Number.isFinite(reserveExpiresAtMs) && reserveExpiresAtMs < nowMs) return null;
    return (parseThresholdEcdsaPresignatureRelayerShareRecord(row?.record_json) as ThresholdEcdsaPresignatureRelayerShareRecord | null);
  }

  async discard(relayerKeyId: string, presignatureId: string): Promise<void> {
    const relayer = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!relayer || !id) return;
    const pool = await this.poolPromise;
    await pool.query(
      `
        DELETE FROM threshold_ecdsa_presignatures
        WHERE namespace = $1 AND relayer_key_id = $2 AND presignature_id = $3 AND state = 'reserved'
      `,
      [this.namespace, relayer, id],
    );
  }
}

export function createThresholdEcdsaSigningStores(input: {
  config?: ThresholdEd25519KeyStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): {
  signingSessionStore: ThresholdEcdsaSigningSessionStore;
  presignaturePool: ThresholdEcdsaPresignaturePool;
  presignSessionStore: ThresholdEcdsaPresignSessionStore;
} {
  const doStores = createCloudflareDurableObjectThresholdEcdsaStores({ config: input.config, logger: input.logger });
  if (doStores) {
    return {
      signingSessionStore: doStores.signingSessionStore,
      presignaturePool: doStores.presignaturePool,
      presignSessionStore: doStores.presignSessionStore,
    };
  }

  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const allowInMemory = toOptionalTrimmedString(config.THRESHOLD_ALLOW_IN_MEMORY_STORES) === '1';
  const requirePersistent = !input.isNode && !allowInMemory;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const signingPrefix = toThresholdEcdsaSigningPrefix(
    toOptionalTrimmedString(config.THRESHOLD_ECDSA_SIGNING_PREFIX)
    || toThresholdEcdsaPrefixFromBase(basePrefix, 'signing'),
  );
  const presignPrefix = toThresholdEcdsaPresignPrefix(
    toOptionalTrimmedString(config.THRESHOLD_ECDSA_PRESIGN_PREFIX)
    || toThresholdEcdsaPrefixFromBase(basePrefix, 'presign'),
  );

  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'in-memory') {
    if (requirePersistent) {
      throw new Error('[threshold-ecdsa] In-memory presign/signing stores are not supported in this runtime; configure Redis/Postgres or Durable Objects');
    }
    return {
      signingSessionStore: new InMemoryThresholdEcdsaSigningSessionStore(),
      presignaturePool: new InMemoryThresholdEcdsaPresignaturePool(),
      presignSessionStore: new InMemoryThresholdEcdsaPresignSessionStore(),
    };
  }

  if (kind === 'upstash-redis-rest') {
    const url = toOptionalTrimmedString((config as any).url) || toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
    const token = toOptionalTrimmedString((config as any).token) || toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
    if (!url || !token) throw new Error('[threshold-ecdsa] upstash-redis-rest selected but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not set');
    return {
      signingSessionStore: new UpstashRedisRestThresholdEcdsaSigningSessionStore({ url, token, keyPrefix: signingPrefix }),
      presignaturePool: new UpstashRedisRestThresholdEcdsaPresignaturePool({ url, token, keyPrefix: presignPrefix }),
      presignSessionStore: new UpstashRedisRestThresholdEcdsaPresignSessionStore({ url, token, keyPrefix: presignPrefix }),
    };
  }

  if (kind === 'redis-tcp') {
    const redisUrl = toOptionalTrimmedString((config as any).redisUrl) || toOptionalTrimmedString(config.REDIS_URL);
    if (!redisUrl) throw new Error('[threshold-ecdsa] redis-tcp selected but REDIS_URL is not set');
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error('[threshold-ecdsa] redis-tcp presign/signing stores are not supported in this runtime; configure Upstash/Redis REST or Durable Objects');
      }
      input.logger.warn('[threshold-ecdsa] redis-tcp is not supported in this runtime; falling back to in-memory');
      return {
        signingSessionStore: new InMemoryThresholdEcdsaSigningSessionStore(),
        presignaturePool: new InMemoryThresholdEcdsaPresignaturePool(),
        presignSessionStore: new InMemoryThresholdEcdsaPresignSessionStore(),
      };
    }
    return {
      signingSessionStore: new RedisTcpThresholdEcdsaSigningSessionStore({ redisUrl, keyPrefix: signingPrefix }),
      presignaturePool: new RedisTcpThresholdEcdsaPresignaturePool({ redisUrl, keyPrefix: presignPrefix }),
      presignSessionStore: new RedisTcpThresholdEcdsaPresignSessionStore({ redisUrl, keyPrefix: presignPrefix }),
    };
  }

  if (kind === 'postgres') {
    if (!input.isNode) {
      throw new Error('[threshold-ecdsa] postgres presign/signing stores are not supported in this runtime');
    }
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl) throw new Error('[threshold-ecdsa] postgres selected but POSTGRES_URL is not set');
    return {
      signingSessionStore: new PostgresThresholdEcdsaSigningSessionStore({ postgresUrl, namespace: signingPrefix }),
      presignaturePool: new PostgresThresholdEcdsaPresignaturePool({ postgresUrl, namespace: presignPrefix }),
      presignSessionStore: new PostgresThresholdEcdsaPresignSessionStore({ postgresUrl, namespace: presignPrefix }),
    };
  }

  // Env-shaped config: prefer Redis/Upstash for presign pools (high churn) and for signing sessions (GETDEL semantics).
  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error('[threshold-ecdsa] Upstash selected but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set');
    }
    input.logger.info('[threshold-ecdsa] Using Upstash REST for presign pool + signing sessions');
    return {
      signingSessionStore: new UpstashRedisRestThresholdEcdsaSigningSessionStore({ url: upstashUrl, token: upstashToken, keyPrefix: signingPrefix }),
      presignaturePool: new UpstashRedisRestThresholdEcdsaPresignaturePool({ url: upstashUrl, token: upstashToken, keyPrefix: presignPrefix }),
      presignSessionStore: new UpstashRedisRestThresholdEcdsaPresignSessionStore({ url: upstashUrl, token: upstashToken, keyPrefix: presignPrefix }),
    };
  }

  const redisUrl = toOptionalTrimmedString(config.REDIS_URL);
  if (redisUrl) {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error('[threshold-ecdsa] REDIS_URL is set but TCP Redis is not supported in this runtime; use Upstash/Redis REST or Durable Objects');
      }
      input.logger.warn('[threshold-ecdsa] REDIS_URL is set but TCP Redis is not supported in this runtime; falling back to in-memory');
      return {
        signingSessionStore: new InMemoryThresholdEcdsaSigningSessionStore(),
        presignaturePool: new InMemoryThresholdEcdsaPresignaturePool(),
        presignSessionStore: new InMemoryThresholdEcdsaPresignSessionStore(),
      };
    }
    input.logger.info('[threshold-ecdsa] Using redis-tcp for presign pool + signing sessions');
    return {
      signingSessionStore: new RedisTcpThresholdEcdsaSigningSessionStore({ redisUrl, keyPrefix: signingPrefix }),
      presignaturePool: new RedisTcpThresholdEcdsaPresignaturePool({ redisUrl, keyPrefix: presignPrefix }),
      presignSessionStore: new RedisTcpThresholdEcdsaPresignSessionStore({ redisUrl, keyPrefix: presignPrefix }),
    };
  }

  const postgresUrl = getPostgresUrlFromConfig(config);
  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error('[threshold-ecdsa] POSTGRES_URL is set but Postgres is not supported in this runtime');
    }
    input.logger.info('[threshold-ecdsa] Using Postgres for presign pool + signing sessions');
    return {
      signingSessionStore: new PostgresThresholdEcdsaSigningSessionStore({ postgresUrl, namespace: signingPrefix }),
      presignaturePool: new PostgresThresholdEcdsaPresignaturePool({ postgresUrl, namespace: presignPrefix }),
      presignSessionStore: new PostgresThresholdEcdsaPresignSessionStore({ postgresUrl, namespace: presignPrefix }),
    };
  }

  if (requirePersistent) {
    throw new Error('[threshold-ecdsa] Presign/signing stores require persistent storage in this runtime; configure UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN or Durable Objects');
  }

  input.logger.info('[threshold-ecdsa] Using in-memory presign pool + signing sessions (non-persistent)');
  return {
    signingSessionStore: new InMemoryThresholdEcdsaSigningSessionStore(),
    presignaturePool: new InMemoryThresholdEcdsaPresignaturePool(),
    presignSessionStore: new InMemoryThresholdEcdsaPresignSessionStore(),
  };
}
