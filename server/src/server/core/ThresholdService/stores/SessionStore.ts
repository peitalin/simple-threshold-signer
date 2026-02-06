import type { NormalizedLogger } from '../../logger';
import type { ThresholdEd25519KeyStoreConfigInput } from '../../types';
import { RedisTcpClient, UpstashRedisRestClient, redisGetdelJson, redisSetJson } from '../kv';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { getPostgresPool, getPostgresUrlFromConfig } from '../../../storage/postgres';
import {
  toThresholdEcdsaPrefixFromBase,
  toThresholdEcdsaSessionPrefix,
  toThresholdEd25519SessionPrefix,
  toThresholdEd25519PrefixFromBase,
  parseThresholdEd25519MpcSessionRecord,
  parseThresholdEd25519CoordinatorSigningSessionRecord,
  parseThresholdEd25519SigningSessionRecord,
  isObject,
} from '../validation';
import {
  createCloudflareDurableObjectThresholdEcdsaStores,
  createCloudflareDurableObjectThresholdEd25519Stores,
} from './CloudflareDurableObjectStore';

export type ThresholdEd25519Commitments = { hiding: string; binding: string };

export type ThresholdEd25519CommitmentsById = Record<string, ThresholdEd25519Commitments>;

export type ThresholdEd25519MpcSessionRecord = {
  expiresAtMs: number;
  relayerKeyId: string;
  purpose: string;
  intentDigestB64u: string;
  signingDigestB64u: string;
  userId: string;
  rpId: string;
  clientVerifyingShareB64u: string;
  participantIds: number[];
};

export type ThresholdEd25519SigningSessionRecord = {
  expiresAtMs: number;
  mpcSessionId: string;
  relayerKeyId: string;
  signingDigestB64u: string;
  userId: string;
  rpId: string;
  clientVerifyingShareB64u: string;
  commitmentsById: ThresholdEd25519CommitmentsById;
  /**
   * Optional relayer signing share material for internal flows (e.g. relayer-fleet cosigners).
   * For normal relayer signing sessions this should be re-derived from key material instead.
   */
  relayerSigningShareB64u?: string;
  relayerNoncesB64u: string;
  participantIds: number[];
};

export type ThresholdEd25519CoordinatorSigningSessionRecord =
  {
    mode: 'cosigner';
    expiresAtMs: number;
    mpcSessionId: string;
    relayerKeyId: string;
    signingDigestB64u: string;
    userId: string;
    rpId: string;
    clientVerifyingShareB64u: string;
    commitmentsById: ThresholdEd25519CommitmentsById;
    participantIds: number[];
    groupPublicKey: string;
    cosignerIds: number[];
    cosignerRelayerUrlsById: Record<string, string>;
    cosignerCoordinatorGrantsById: Record<string, string>;
    relayerVerifyingSharesById: Record<string, string>;
  };

export interface ThresholdEd25519SessionStore {
  putMpcSession(id: string, record: ThresholdEd25519MpcSessionRecord, ttlMs: number): Promise<void>;
  takeMpcSession(id: string): Promise<ThresholdEd25519MpcSessionRecord | null>;
  putSigningSession(id: string, record: ThresholdEd25519SigningSessionRecord, ttlMs: number): Promise<void>;
  takeSigningSession(id: string): Promise<ThresholdEd25519SigningSessionRecord | null>;
  putCoordinatorSigningSession(id: string, record: ThresholdEd25519CoordinatorSigningSessionRecord, ttlMs: number): Promise<void>;
  takeCoordinatorSigningSession(id: string): Promise<ThresholdEd25519CoordinatorSigningSessionRecord | null>;
}

class InMemoryThresholdEd25519SessionStore implements ThresholdEd25519SessionStore {
  private readonly map = new Map<string, { value: unknown; expiresAtMs: number }>();
  private readonly keyPrefix: string;
  private readonly coordinatorPrefix: string;

  constructor(input: { keyPrefix?: string }) {
    this.keyPrefix = toThresholdEd25519SessionPrefix(input.keyPrefix);
    this.coordinatorPrefix = `${this.keyPrefix}coord:`;
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  private coordKey(id: string): string {
    return `${this.coordinatorPrefix}${id}`;
  }

  private getRaw(key: string): unknown | null {
    const entry = this.map.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAtMs) {
      this.map.delete(key);
      return null;
    }
    return entry.value;
  }

  async putMpcSession(id: string, record: ThresholdEd25519MpcSessionRecord, ttlMs: number): Promise<void> {
    const key = this.key(id);
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    this.map.set(key, { value: record, expiresAtMs });
  }

  async takeMpcSession(id: string): Promise<ThresholdEd25519MpcSessionRecord | null> {
    const key = this.key(id);
    const raw = this.getRaw(key);
    this.map.delete(key);
    return parseThresholdEd25519MpcSessionRecord(raw);
  }

  async putSigningSession(id: string, record: ThresholdEd25519SigningSessionRecord, ttlMs: number): Promise<void> {
    const key = this.key(id);
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    this.map.set(key, { value: record, expiresAtMs });
  }

  async takeSigningSession(id: string): Promise<ThresholdEd25519SigningSessionRecord | null> {
    const key = this.key(id);
    const raw = this.getRaw(key);
    this.map.delete(key);
    return parseThresholdEd25519SigningSessionRecord(raw);
  }

  async putCoordinatorSigningSession(id: string, record: ThresholdEd25519CoordinatorSigningSessionRecord, ttlMs: number): Promise<void> {
    const key = this.coordKey(id);
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    this.map.set(key, { value: record, expiresAtMs });
  }

  async takeCoordinatorSigningSession(id: string): Promise<ThresholdEd25519CoordinatorSigningSessionRecord | null> {
    const key = this.coordKey(id);
    const raw = this.getRaw(key);
    this.map.delete(key);
    return parseThresholdEd25519CoordinatorSigningSessionRecord(raw);
  }
}

class UpstashRedisRestThresholdEd25519SessionStore implements ThresholdEd25519SessionStore {
  private readonly client: UpstashRedisRestClient;
  private readonly keyPrefix: string;
  private readonly coordinatorPrefix: string;

  constructor(input: { url: string; token: string; keyPrefix?: string }) {
    const url = toOptionalTrimmedString(input.url);
    const token = toOptionalTrimmedString(input.token);
    if (!url) throw new Error('Upstash session store missing url');
    if (!token) throw new Error('Upstash session store missing token');
    this.client = new UpstashRedisRestClient({ url, token });
    this.keyPrefix = toThresholdEd25519SessionPrefix(input.keyPrefix);
    this.coordinatorPrefix = `${this.keyPrefix}coord:`;
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  private coordKey(id: string): string {
    return `${this.coordinatorPrefix}${id}`;
  }

  async putMpcSession(id: string, record: ThresholdEd25519MpcSessionRecord, ttlMs: number): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing mpcSessionId');
    await this.client.setJson(this.key(k), record, ttlMs);
  }

  async takeMpcSession(id: string): Promise<ThresholdEd25519MpcSessionRecord | null> {
    const k = id;
    if (!k) return null;
    const raw = await this.client.getdelJson(this.key(k));
    return parseThresholdEd25519MpcSessionRecord(raw);
  }

  async putSigningSession(id: string, record: ThresholdEd25519SigningSessionRecord, ttlMs: number): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing signingSessionId');
    await this.client.setJson(this.key(k), record, ttlMs);
  }

  async takeSigningSession(id: string): Promise<ThresholdEd25519SigningSessionRecord | null> {
    const k = id;
    if (!k) return null;
    const raw = await this.client.getdelJson(this.key(k));
    return parseThresholdEd25519SigningSessionRecord(raw);
  }

  async putCoordinatorSigningSession(id: string, record: ThresholdEd25519CoordinatorSigningSessionRecord, ttlMs: number): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing coordinator signingSessionId');
    await this.client.setJson(this.coordKey(k), record, ttlMs);
  }

  async takeCoordinatorSigningSession(id: string): Promise<ThresholdEd25519CoordinatorSigningSessionRecord | null> {
    const k = id;
    if (!k) return null;
    const raw = await this.client.getdelJson(this.coordKey(k));
    return parseThresholdEd25519CoordinatorSigningSessionRecord(raw);
  }
}

class RedisTcpThresholdEd25519SessionStore implements ThresholdEd25519SessionStore {
  private readonly client: RedisTcpClient;
  private readonly keyPrefix: string;
  private readonly coordinatorPrefix: string;

  constructor(input: { redisUrl: string; keyPrefix?: string }) {
    const url = toOptionalTrimmedString(input.redisUrl);
    if (!url) throw new Error('redis-tcp session store missing redisUrl');
    this.client = new RedisTcpClient(url);
    this.keyPrefix = toThresholdEd25519SessionPrefix(input.keyPrefix);
    this.coordinatorPrefix = `${this.keyPrefix}coord:`;
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  private coordKey(id: string): string {
    return `${this.coordinatorPrefix}${id}`;
  }

  async putMpcSession(id: string, record: ThresholdEd25519MpcSessionRecord, ttlMs: number): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing mpcSessionId');
    await redisSetJson(this.client, this.key(k), record, ttlMs);
  }

  async takeMpcSession(id: string): Promise<ThresholdEd25519MpcSessionRecord | null> {
    const k = id;
    if (!k) return null;
    const raw = await redisGetdelJson(this.client, this.key(k));
    return parseThresholdEd25519MpcSessionRecord(raw);
  }

  async putSigningSession(id: string, record: ThresholdEd25519SigningSessionRecord, ttlMs: number): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing signingSessionId');
    await redisSetJson(this.client, this.key(k), record, ttlMs);
  }

  async takeSigningSession(id: string): Promise<ThresholdEd25519SigningSessionRecord | null> {
    const k = id;
    if (!k) return null;
    const raw = await redisGetdelJson(this.client, this.key(k));
    return parseThresholdEd25519SigningSessionRecord(raw);
  }

  async putCoordinatorSigningSession(id: string, record: ThresholdEd25519CoordinatorSigningSessionRecord, ttlMs: number): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing coordinator signingSessionId');
    await redisSetJson(this.client, this.coordKey(k), record, ttlMs);
  }

  async takeCoordinatorSigningSession(id: string): Promise<ThresholdEd25519CoordinatorSigningSessionRecord | null> {
    const k = id;
    if (!k) return null;
    const raw = await redisGetdelJson(this.client, this.coordKey(k));
    return parseThresholdEd25519CoordinatorSigningSessionRecord(raw);
  }
}

class PostgresThresholdEd25519SessionStore implements ThresholdEd25519SessionStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  private async insertOrUpdate(input: {
    kind: 'mpc' | 'signing' | 'coordinator';
    sessionId: string;
    record: unknown;
    expiresAtMs: number;
  }): Promise<void> {
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO tatchi_threshold_ed25519_sessions (namespace, kind, session_id, record_json, expires_at_ms)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (namespace, kind, session_id)
        DO UPDATE SET record_json = EXCLUDED.record_json, expires_at_ms = EXCLUDED.expires_at_ms
      `,
      [this.namespace, input.kind, input.sessionId, input.record, Math.floor(input.expiresAtMs)],
    );
  }

  private async takeRow(kind: 'mpc' | 'signing' | 'coordinator', sessionId: string): Promise<unknown | null> {
    const pool = await this.poolPromise;
    const nowMs = Date.now();
    const { rows } = await pool.query(
      `
        DELETE FROM tatchi_threshold_ed25519_sessions
        WHERE namespace = $1 AND kind = $2 AND session_id = $3 AND expires_at_ms > $4
        RETURNING record_json
      `,
      [this.namespace, kind, sessionId, nowMs],
    );
    return rows[0]?.record_json ?? null;
  }

  async putMpcSession(id: string, record: ThresholdEd25519MpcSessionRecord, ttlMs: number): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing mpcSessionId');
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    const storedRecord = { ...record, expiresAtMs };
    await this.insertOrUpdate({ kind: 'mpc', sessionId: k, record: storedRecord, expiresAtMs });
  }

  async takeMpcSession(id: string): Promise<ThresholdEd25519MpcSessionRecord | null> {
    const k = id;
    if (!k) return null;
    const raw = await this.takeRow('mpc', k);
    return parseThresholdEd25519MpcSessionRecord(raw);
  }

  async putSigningSession(id: string, record: ThresholdEd25519SigningSessionRecord, ttlMs: number): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing signingSessionId');
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    const storedRecord = { ...record, expiresAtMs };
    await this.insertOrUpdate({ kind: 'signing', sessionId: k, record: storedRecord, expiresAtMs });
  }

  async takeSigningSession(id: string): Promise<ThresholdEd25519SigningSessionRecord | null> {
    const k = id;
    if (!k) return null;
    const raw = await this.takeRow('signing', k);
    return parseThresholdEd25519SigningSessionRecord(raw);
  }

  async putCoordinatorSigningSession(id: string, record: ThresholdEd25519CoordinatorSigningSessionRecord, ttlMs: number): Promise<void> {
    const k = id;
    if (!k) throw new Error('Missing coordinator signingSessionId');
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    const storedRecord = { ...record, expiresAtMs };
    await this.insertOrUpdate({ kind: 'coordinator', sessionId: k, record: storedRecord, expiresAtMs });
  }

  async takeCoordinatorSigningSession(id: string): Promise<ThresholdEd25519CoordinatorSigningSessionRecord | null> {
    const k = id;
    if (!k) return null;
    const raw = await this.takeRow('coordinator', k);
    return parseThresholdEd25519CoordinatorSigningSessionRecord(raw);
  }
}

export function createThresholdEd25519SessionStore(input: {
  config?: ThresholdEd25519KeyStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): ThresholdEd25519SessionStore {
  const doStores = createCloudflareDurableObjectThresholdEd25519Stores({ config: input.config, logger: input.logger });
  if (doStores) return doStores.sessionStore;

  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const allowInMemory = toOptionalTrimmedString(config.THRESHOLD_ALLOW_IN_MEMORY_STORES) === '1';
  const requirePersistent = !input.isNode && !allowInMemory;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const envPrefix =
    toOptionalTrimmedString(config.THRESHOLD_ED25519_SESSION_PREFIX)
    || toThresholdEd25519PrefixFromBase(basePrefix, 'sess')
    || '';

  // Explicit config object
  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'in-memory') {
    if (requirePersistent) {
      throw new Error('[threshold-ed25519] In-memory session store is not supported in this runtime; configure Upstash/Redis or Durable Objects');
    }
    return new InMemoryThresholdEd25519SessionStore({ keyPrefix: envPrefix || undefined });
  }
  if (kind === 'upstash-redis-rest') {
    return new UpstashRedisRestThresholdEd25519SessionStore({
      url: toOptionalTrimmedString(config.url) || toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL),
      token: toOptionalTrimmedString(config.token) || toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }
  if (kind === 'redis-tcp') {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error('[threshold-ed25519] redis-tcp session store is not supported in this runtime; configure Upstash/Redis REST or Durable Objects');
      }
      input.logger.warn('[threshold-ed25519] redis-tcp session store is not supported in this runtime; falling back to in-memory');
      return new InMemoryThresholdEd25519SessionStore({ keyPrefix: envPrefix || undefined });
    }
    return new RedisTcpThresholdEd25519SessionStore({
      redisUrl: toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }
  if (kind === 'postgres') {
    if (!input.isNode) {
      throw new Error('[threshold-ed25519] postgres session store is not supported in this runtime');
    }
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl) throw new Error('[threshold-ed25519] postgres session store enabled but POSTGRES_URL is not set');
    input.logger.info('[threshold-ed25519] Using Postgres session store for signing session persistence');
    return new PostgresThresholdEd25519SessionStore({ postgresUrl, namespace: toOptionalTrimmedString(config.keyPrefix) || envPrefix });
  }

  // Env-shaped config: prefer Redis/Upstash for session storage (TTL + lower Postgres churn).
  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error('Upstash session store enabled but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set');
    }
    input.logger.info('[threshold-ed25519] Using Upstash REST session store for signing session persistence');
    return new UpstashRedisRestThresholdEd25519SessionStore({ url: upstashUrl, token: upstashToken, keyPrefix: envPrefix || undefined });
  }

  const redisUrl = toOptionalTrimmedString(config.REDIS_URL);
  if (redisUrl) {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error('[threshold-ed25519] REDIS_URL is set but TCP Redis is not supported in this runtime; use Upstash/Redis REST or Durable Objects');
      }
      input.logger.warn('[threshold-ed25519] REDIS_URL is set but TCP Redis is not supported in this runtime; falling back to in-memory');
      return new InMemoryThresholdEd25519SessionStore({ keyPrefix: envPrefix || undefined });
    }
    input.logger.info('[threshold-ed25519] Using redis-tcp session store for signing session persistence');
    return new RedisTcpThresholdEd25519SessionStore({ redisUrl, keyPrefix: envPrefix || undefined });
  }

  const postgresUrl = getPostgresUrlFromConfig(config);
  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error('[threshold-ed25519] POSTGRES_URL is set but Postgres is not supported in this runtime');
    }
    input.logger.info('[threshold-ed25519] Using Postgres session store for signing session persistence');
    return new PostgresThresholdEd25519SessionStore({ postgresUrl, namespace: envPrefix || '' });
  }

  if (requirePersistent) {
    throw new Error('[threshold-ed25519] Threshold signing sessions require persistent storage in this runtime; configure UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN or Durable Objects');
  }
  input.logger.info('[threshold-ed25519] Using in-memory session store for threshold signing sessions (non-persistent)');
  return new InMemoryThresholdEd25519SessionStore({ keyPrefix: envPrefix || undefined });
}

export function createThresholdEcdsaSessionStore(input: {
  config?: ThresholdEd25519KeyStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): ThresholdEd25519SessionStore {
  const doStores = createCloudflareDurableObjectThresholdEcdsaStores({ config: input.config, logger: input.logger });
  if (doStores) return doStores.sessionStore;

  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const allowInMemory = toOptionalTrimmedString(config.THRESHOLD_ALLOW_IN_MEMORY_STORES) === '1';
  const requirePersistent = !input.isNode && !allowInMemory;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const envPrefix = toThresholdEcdsaSessionPrefix(
    toOptionalTrimmedString(config.THRESHOLD_ECDSA_SESSION_PREFIX)
    || toThresholdEcdsaPrefixFromBase(basePrefix, 'sess'),
  );

  // Explicit config object
  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'in-memory') {
    if (requirePersistent) {
      throw new Error('[threshold-ecdsa] In-memory session store is not supported in this runtime; configure Upstash/Redis or Durable Objects');
    }
    return new InMemoryThresholdEd25519SessionStore({ keyPrefix: envPrefix });
  }
  if (kind === 'upstash-redis-rest') {
    return new UpstashRedisRestThresholdEd25519SessionStore({
      url: toOptionalTrimmedString(config.url) || toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL),
      token: toOptionalTrimmedString(config.token) || toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }
  if (kind === 'redis-tcp') {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error('[threshold-ecdsa] redis-tcp session store is not supported in this runtime; configure Upstash/Redis REST or Durable Objects');
      }
      input.logger.warn('[threshold-ecdsa] redis-tcp session store is not supported in this runtime; falling back to in-memory');
      return new InMemoryThresholdEd25519SessionStore({ keyPrefix: envPrefix });
    }
    return new RedisTcpThresholdEd25519SessionStore({
      redisUrl: toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }
  if (kind === 'postgres') {
    if (!input.isNode) {
      throw new Error('[threshold-ecdsa] postgres session store is not supported in this runtime');
    }
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl) throw new Error('[threshold-ecdsa] postgres session store enabled but POSTGRES_URL is not set');
    input.logger.info('[threshold-ecdsa] Using Postgres session store for signing session persistence');
    return new PostgresThresholdEd25519SessionStore({ postgresUrl, namespace: toOptionalTrimmedString(config.keyPrefix) || envPrefix });
  }

  // Env-shaped config: prefer Redis/Upstash for session storage (TTL + lower Postgres churn).
  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error('Upstash session store enabled but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set');
    }
    input.logger.info('[threshold-ecdsa] Using Upstash REST session store for signing session persistence');
    return new UpstashRedisRestThresholdEd25519SessionStore({ url: upstashUrl, token: upstashToken, keyPrefix: envPrefix });
  }

  const redisUrl = toOptionalTrimmedString(config.REDIS_URL);
  if (redisUrl) {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error('[threshold-ecdsa] REDIS_URL is set but TCP Redis is not supported in this runtime; use Upstash/Redis REST or Durable Objects');
      }
      input.logger.warn('[threshold-ecdsa] REDIS_URL is set but TCP Redis is not supported in this runtime; falling back to in-memory');
      return new InMemoryThresholdEd25519SessionStore({ keyPrefix: envPrefix });
    }
    input.logger.info('[threshold-ecdsa] Using redis-tcp session store for signing session persistence');
    return new RedisTcpThresholdEd25519SessionStore({ redisUrl, keyPrefix: envPrefix });
  }

  const postgresUrl = getPostgresUrlFromConfig(config);
  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error('[threshold-ecdsa] POSTGRES_URL is set but Postgres is not supported in this runtime');
    }
    input.logger.info('[threshold-ecdsa] Using Postgres session store for signing session persistence');
    return new PostgresThresholdEd25519SessionStore({ postgresUrl, namespace: envPrefix });
  }

  if (requirePersistent) {
    throw new Error('[threshold-ecdsa] Threshold signing sessions require persistent storage in this runtime; configure UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN or Durable Objects');
  }
  input.logger.info('[threshold-ecdsa] Using in-memory session store for threshold signing sessions (non-persistent)');
  return new InMemoryThresholdEd25519SessionStore({ keyPrefix: envPrefix });
}
