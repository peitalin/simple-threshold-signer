import type { NormalizedLogger } from '../../logger';
import type { ThresholdEd25519KeyStoreConfigInput } from '../../types';
import { RedisTcpClient, UpstashRedisRestClient, redisGetJson, redisSetJson } from '../kv';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { getPostgresPool, getPostgresUrlFromConfig } from '../../../storage/postgres';
import {
  isObject,
  toThresholdEcdsaAuthPrefix,
  toThresholdEcdsaPrefixFromBase,
  toThresholdEd25519AuthPrefix,
  toThresholdEd25519PrefixFromBase,
  parseThresholdEd25519AuthSessionRecord,
} from '../validation';
import {
  createCloudflareDurableObjectThresholdEcdsaStores,
  createCloudflareDurableObjectThresholdEd25519Stores,
} from './CloudflareDurableObjectStore';

export type ThresholdEd25519AuthSessionRecord = {
  expiresAtMs: number;
  relayerKeyId: string;
  userId: string;
  rpId: string;
  participantIds: number[];
};

export type ThresholdEd25519AuthConsumeUsesResult =
  | { ok: true; remainingUses: number }
  | { ok: false; code: string; message: string };

export interface ThresholdEd25519AuthSessionStore {
  putSession(
    id: string,
    record: ThresholdEd25519AuthSessionRecord,
    opts: { ttlMs: number; remainingUses: number },
  ): Promise<void>;
  getSession(id: string): Promise<ThresholdEd25519AuthSessionRecord | null>;
  /**
   * Consume one use from the session counter without fetching the session record.
   *
   * This enables session-token-only authorization flows where scope/expiry are enforced from
   * signed JWT claims instead of a KV-stored record, reducing KV read-after-write consistency issues.
   */
  consumeUseCount(id: string): Promise<ThresholdEd25519AuthConsumeUsesResult>;
}

class InMemoryThresholdEd25519AuthSessionStore implements ThresholdEd25519AuthSessionStore {
  private readonly keyPrefix: string;
  private readonly map = new Map<string, { record: ThresholdEd25519AuthSessionRecord; remainingUses: number; expiresAtMs: number }>();

  constructor(input: { keyPrefix?: string }) {
    this.keyPrefix = toThresholdEd25519AuthPrefix(input.keyPrefix);
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  async putSession(
    id: string,
    record: ThresholdEd25519AuthSessionRecord,
    opts: { ttlMs: number; remainingUses: number },
  ): Promise<void> {
    const key = this.key(id);
    const ttlMs = Math.max(0, Number(opts.ttlMs) || 0);
    const expiresAtMs = Date.now() + ttlMs;
    this.map.set(key, { record, remainingUses: Math.max(0, Number(opts.remainingUses) || 0), expiresAtMs });
  }

  async getSession(id: string): Promise<ThresholdEd25519AuthSessionRecord | null> {
    const key = this.key(id);
    const entry = this.map.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAtMs) {
      this.map.delete(key);
      return null;
    }
    return entry.record;
  }

  async consumeUseCount(id: string): Promise<ThresholdEd25519AuthConsumeUsesResult> {
    const key = this.key(id);
    const entry = this.map.get(key);
    if (!entry) return { ok: false, code: 'unauthorized', message: 'threshold session expired or invalid' };
    if (Date.now() > entry.expiresAtMs) {
      this.map.delete(key);
      return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
    }
    if (entry.remainingUses <= 0) {
      return { ok: false, code: 'unauthorized', message: 'threshold session exhausted' };
    }
    entry.remainingUses -= 1;
    return { ok: true, remainingUses: entry.remainingUses };
  }
}

class UpstashRedisRestThresholdEd25519AuthSessionStore implements ThresholdEd25519AuthSessionStore {
  private readonly client: UpstashRedisRestClient;
  private readonly keyPrefix: string;

  constructor(input: { url: string; token: string; keyPrefix?: string }) {
    const url = toOptionalTrimmedString(input.url);
    const token = toOptionalTrimmedString(input.token);
    if (!url) throw new Error('Upstash auth session store missing url');
    if (!token) throw new Error('Upstash auth session store missing token');
    this.client = new UpstashRedisRestClient({ url, token });
    this.keyPrefix = toThresholdEd25519AuthPrefix(input.keyPrefix);
  }

  private metaKey(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  private usesKey(id: string): string {
    return `${this.keyPrefix}${id}:uses`;
  }

  async putSession(
    id: string,
    record: ThresholdEd25519AuthSessionRecord,
    opts: { ttlMs: number; remainingUses: number },
  ): Promise<void> {
    const ttlMs = Math.max(0, Number(opts.ttlMs) || 0);
    await this.client.setJson(this.metaKey(id), record, ttlMs);
    await this.client.setRaw(this.usesKey(id), String(Math.max(0, Number(opts.remainingUses) || 0)), ttlMs);
  }

  async getSession(id: string): Promise<ThresholdEd25519AuthSessionRecord | null> {
    const raw = await this.client.getJson(this.metaKey(id));
    return parseThresholdEd25519AuthSessionRecord(raw);
  }

  async consumeUseCount(id: string): Promise<ThresholdEd25519AuthConsumeUsesResult> {
    try {
      const remainingUses = await this.client.incrby(this.usesKey(id), -1);
      if (remainingUses < 0) {
        return { ok: false, code: 'unauthorized', message: 'threshold session exhausted' };
      }
      return { ok: true, remainingUses };
    } catch (e: unknown) {
      const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || 'Failed to consume threshold session');
      return { ok: false, code: 'internal', message: msg };
    }
  }
}

class RedisTcpThresholdEd25519AuthSessionStore implements ThresholdEd25519AuthSessionStore {
  private readonly client: RedisTcpClient;
  private readonly keyPrefix: string;

  constructor(input: { redisUrl: string; keyPrefix?: string }) {
    const url = toOptionalTrimmedString(input.redisUrl);
    if (!url) throw new Error('redis-tcp auth session store missing redisUrl');
    this.client = new RedisTcpClient(url);
    this.keyPrefix = toThresholdEd25519AuthPrefix(input.keyPrefix);
  }

  private metaKey(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  private usesKey(id: string): string {
    return `${this.keyPrefix}${id}:uses`;
  }

  async putSession(
    id: string,
    record: ThresholdEd25519AuthSessionRecord,
    opts: { ttlMs: number; remainingUses: number },
  ): Promise<void> {
    const ttlMs = Math.max(0, Number(opts.ttlMs) || 0);
    await redisSetJson(this.client, this.metaKey(id), record, ttlMs);
    const ttlSeconds = Math.max(1, Math.ceil(ttlMs / 1000));
    const uses = String(Math.max(0, Number(opts.remainingUses) || 0));
    const resp = await this.client.send(['SET', this.usesKey(id), uses, 'EX', String(ttlSeconds)]);
    if (resp.type === 'error') throw new Error(`Redis SET error: ${resp.value}`);
  }

  async getSession(id: string): Promise<ThresholdEd25519AuthSessionRecord | null> {
    const raw = await redisGetJson(this.client, this.metaKey(id));
    return parseThresholdEd25519AuthSessionRecord(raw);
  }

  async consumeUseCount(id: string): Promise<ThresholdEd25519AuthConsumeUsesResult> {
    try {
      const resp = await this.client.send(['INCRBY', this.usesKey(id), '-1']);
      if (resp.type === 'error') return { ok: false, code: 'internal', message: `Redis INCRBY error: ${resp.value}` };
      const remainingUses = resp.type === 'integer' ? resp.value : Number(resp.value ?? 0);
      if (!Number.isFinite(remainingUses)) {
        return { ok: false, code: 'internal', message: 'Redis INCRBY returned non-integer value' };
      }
      if (remainingUses < 0) {
        return { ok: false, code: 'unauthorized', message: 'threshold session exhausted' };
      }
      return { ok: true, remainingUses };
    } catch (e: unknown) {
      const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || 'Failed to consume threshold session');
      return { ok: false, code: 'internal', message: msg };
    }
  }
}

class PostgresThresholdEd25519AuthSessionStore implements ThresholdEd25519AuthSessionStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async putSession(
    id: string,
    record: ThresholdEd25519AuthSessionRecord,
    opts: { ttlMs: number; remainingUses: number },
  ): Promise<void> {
    const ttlMs = Math.max(0, Number(opts.ttlMs) || 0);
    const expiresAtMs = Date.now() + ttlMs;
    const remainingUses = Math.max(0, Number(opts.remainingUses) || 0);
    const storedRecord = { ...record, expiresAtMs };
    const parsed = parseThresholdEd25519AuthSessionRecord(storedRecord);
    if (!parsed) throw new Error('Invalid threshold auth session record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO tatchi_threshold_ed25519_sessions (namespace, kind, session_id, record_json, expires_at_ms, remaining_uses)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (namespace, kind, session_id)
        DO UPDATE SET record_json = EXCLUDED.record_json, expires_at_ms = EXCLUDED.expires_at_ms, remaining_uses = EXCLUDED.remaining_uses
      `,
      [this.namespace, 'auth', id, parsed, expiresAtMs, remainingUses],
    );
  }

  async getSession(id: string): Promise<ThresholdEd25519AuthSessionRecord | null> {
    const pool = await this.poolPromise;
    const nowMs = Date.now();
    const { rows } = await pool.query(
      `
        SELECT record_json
        FROM tatchi_threshold_ed25519_sessions
        WHERE namespace = $1 AND kind = $2 AND session_id = $3 AND expires_at_ms > $4
        LIMIT 1
      `,
      [this.namespace, 'auth', id, nowMs],
    );
    return parseThresholdEd25519AuthSessionRecord(rows[0]?.record_json);
  }

  private async explainMissing(id: string, nowMs: number): Promise<{ code: string; message: string }> {
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT expires_at_ms, remaining_uses
        FROM tatchi_threshold_ed25519_sessions
        WHERE namespace = $1 AND kind = $2 AND session_id = $3
        LIMIT 1
      `,
      [this.namespace, 'auth', id],
    );
    const row = rows[0];
    if (!row) return { code: 'unauthorized', message: 'threshold session expired or invalid' };
    const expiresAtMs = typeof row.expires_at_ms === 'number' ? row.expires_at_ms : Number(row.expires_at_ms);
    const remainingUses = typeof row.remaining_uses === 'number' ? row.remaining_uses : Number(row.remaining_uses);
    if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) return { code: 'unauthorized', message: 'threshold session expired' };
    if (Number.isFinite(remainingUses) && remainingUses <= 0) return { code: 'unauthorized', message: 'threshold session exhausted' };
    return { code: 'unauthorized', message: 'threshold session expired or invalid' };
  }

  async consumeUseCount(id: string): Promise<ThresholdEd25519AuthConsumeUsesResult> {
    try {
      const pool = await this.poolPromise;
      const nowMs = Date.now();
      const { rows } = await pool.query(
        `
          UPDATE tatchi_threshold_ed25519_sessions
          SET remaining_uses = remaining_uses - 1
          WHERE namespace = $1 AND kind = $2 AND session_id = $3 AND expires_at_ms > $4 AND remaining_uses > 0
          RETURNING remaining_uses
        `,
        [this.namespace, 'auth', id, nowMs],
      );
      const row = rows[0];
      if (!row) {
        const reason = await this.explainMissing(id, nowMs);
        return { ok: false, code: reason.code, message: reason.message };
      }
      const remainingUses = typeof row.remaining_uses === 'number' ? row.remaining_uses : Number(row.remaining_uses);
      if (!Number.isFinite(remainingUses)) return { ok: false, code: 'internal', message: 'Postgres returned invalid remainingUses' };
      return { ok: true, remainingUses };
    } catch (e: unknown) {
      const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || 'Failed to consume threshold session');
      return { ok: false, code: 'internal', message: msg };
    }
  }
}

export function createThresholdEd25519AuthSessionStore(input: {
  config?: ThresholdEd25519KeyStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): ThresholdEd25519AuthSessionStore {
  const doStores = createCloudflareDurableObjectThresholdEd25519Stores({ config: input.config, logger: input.logger });
  if (doStores) return doStores.authSessionStore;

  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const allowInMemory = toOptionalTrimmedString(config.THRESHOLD_ALLOW_IN_MEMORY_STORES) === '1';
  const requirePersistent = !input.isNode && !allowInMemory;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const envPrefix =
    toOptionalTrimmedString(config.THRESHOLD_ED25519_AUTH_PREFIX)
    || toThresholdEd25519PrefixFromBase(basePrefix, 'auth')
    || '';

  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'in-memory') {
    if (requirePersistent) {
      throw new Error('[threshold-ed25519] In-memory auth session store is not supported in this runtime; configure Upstash/Redis or Durable Objects');
    }
    return new InMemoryThresholdEd25519AuthSessionStore({ keyPrefix: envPrefix || undefined });
  }
  if (kind === 'upstash-redis-rest') {
    return new UpstashRedisRestThresholdEd25519AuthSessionStore({
      url: toOptionalTrimmedString(config.url) || toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL),
      token: toOptionalTrimmedString(config.token) || toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }
  if (kind === 'redis-tcp') {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error('[threshold-ed25519] redis-tcp auth session store is not supported in this runtime; configure Upstash/Redis REST or Durable Objects');
      }
      input.logger.warn('[threshold-ed25519] redis-tcp auth session store is not supported in this runtime; falling back to in-memory');
      return new InMemoryThresholdEd25519AuthSessionStore({ keyPrefix: envPrefix || undefined });
    }
    return new RedisTcpThresholdEd25519AuthSessionStore({
      redisUrl: toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }
  if (kind === 'postgres') {
    if (!input.isNode) {
      throw new Error('[threshold-ed25519] postgres auth session store is not supported in this runtime');
    }
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl) throw new Error('[threshold-ed25519] postgres auth session store enabled but POSTGRES_URL is not set');
    input.logger.info('[threshold-ed25519] Using Postgres store for threshold auth sessions');
    return new PostgresThresholdEd25519AuthSessionStore({ postgresUrl, namespace: toOptionalTrimmedString(config.keyPrefix) || envPrefix });
  }

  // Env-shaped config: prefer Redis/Upstash for auth session storage (TTL + counters) to avoid Postgres churn.
  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error('Upstash auth session store enabled but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set');
    }
    input.logger.info('[threshold-ed25519] Using Upstash REST store for threshold auth sessions');
    return new UpstashRedisRestThresholdEd25519AuthSessionStore({ url: upstashUrl, token: upstashToken, keyPrefix: envPrefix || undefined });
  }

  const redisUrl = toOptionalTrimmedString(config.REDIS_URL);
  if (redisUrl) {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error('[threshold-ed25519] REDIS_URL is set but TCP Redis is not supported in this runtime; use Upstash/Redis REST or Durable Objects');
      }
      input.logger.warn('[threshold-ed25519] REDIS_URL is set but TCP Redis is not supported in this runtime; falling back to in-memory');
      return new InMemoryThresholdEd25519AuthSessionStore({ keyPrefix: envPrefix || undefined });
    }
    input.logger.info('[threshold-ed25519] Using redis-tcp store for threshold auth sessions');
    return new RedisTcpThresholdEd25519AuthSessionStore({ redisUrl, keyPrefix: envPrefix || undefined });
  }

  const postgresUrl = getPostgresUrlFromConfig(config);
  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error('[threshold-ed25519] POSTGRES_URL is set but Postgres is not supported in this runtime');
    }
    input.logger.info('[threshold-ed25519] Using Postgres store for threshold auth sessions');
    return new PostgresThresholdEd25519AuthSessionStore({ postgresUrl, namespace: envPrefix || '' });
  }

  if (requirePersistent) {
    throw new Error('[threshold-ed25519] Threshold auth sessions require persistent storage in this runtime; configure UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN or Durable Objects');
  }
  input.logger.info('[threshold-ed25519] Using in-memory auth session store for threshold sessions (non-persistent)');
  return new InMemoryThresholdEd25519AuthSessionStore({ keyPrefix: envPrefix || undefined });
}

export function createThresholdEcdsaAuthSessionStore(input: {
  config?: ThresholdEd25519KeyStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): ThresholdEd25519AuthSessionStore {
  const doStores = createCloudflareDurableObjectThresholdEcdsaStores({ config: input.config, logger: input.logger });
  if (doStores) return doStores.authSessionStore;

  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const allowInMemory = toOptionalTrimmedString(config.THRESHOLD_ALLOW_IN_MEMORY_STORES) === '1';
  const requirePersistent = !input.isNode && !allowInMemory;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const envPrefix = toThresholdEcdsaAuthPrefix(
    toOptionalTrimmedString(config.THRESHOLD_ECDSA_AUTH_PREFIX)
    || toThresholdEcdsaPrefixFromBase(basePrefix, 'auth'),
  );

  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'in-memory') {
    if (requirePersistent) {
      throw new Error('[threshold-ecdsa] In-memory auth session store is not supported in this runtime; configure Upstash/Redis or Durable Objects');
    }
    return new InMemoryThresholdEd25519AuthSessionStore({ keyPrefix: envPrefix });
  }
  if (kind === 'upstash-redis-rest') {
    return new UpstashRedisRestThresholdEd25519AuthSessionStore({
      url: toOptionalTrimmedString(config.url) || toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL),
      token: toOptionalTrimmedString(config.token) || toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }
  if (kind === 'redis-tcp') {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error('[threshold-ecdsa] redis-tcp auth session store is not supported in this runtime; configure Upstash/Redis REST or Durable Objects');
      }
      input.logger.warn('[threshold-ecdsa] redis-tcp auth session store is not supported in this runtime; falling back to in-memory');
      return new InMemoryThresholdEd25519AuthSessionStore({ keyPrefix: envPrefix });
    }
    return new RedisTcpThresholdEd25519AuthSessionStore({
      redisUrl: toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }
  if (kind === 'postgres') {
    if (!input.isNode) {
      throw new Error('[threshold-ecdsa] postgres auth session store is not supported in this runtime');
    }
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl) throw new Error('[threshold-ecdsa] postgres auth session store enabled but POSTGRES_URL is not set');
    input.logger.info('[threshold-ecdsa] Using Postgres store for threshold auth sessions');
    return new PostgresThresholdEd25519AuthSessionStore({ postgresUrl, namespace: toOptionalTrimmedString(config.keyPrefix) || envPrefix });
  }

  // Env-shaped config: prefer Redis/Upstash for auth session storage (TTL + counters) to avoid Postgres churn.
  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error('Upstash auth session store enabled but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set');
    }
    input.logger.info('[threshold-ecdsa] Using Upstash REST store for threshold auth sessions');
    return new UpstashRedisRestThresholdEd25519AuthSessionStore({ url: upstashUrl, token: upstashToken, keyPrefix: envPrefix });
  }

  const redisUrl = toOptionalTrimmedString(config.REDIS_URL);
  if (redisUrl) {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error('[threshold-ecdsa] REDIS_URL is set but TCP Redis is not supported in this runtime; use Upstash/Redis REST or Durable Objects');
      }
      input.logger.warn('[threshold-ecdsa] REDIS_URL is set but TCP Redis is not supported in this runtime; falling back to in-memory');
      return new InMemoryThresholdEd25519AuthSessionStore({ keyPrefix: envPrefix });
    }
    input.logger.info('[threshold-ecdsa] Using redis-tcp store for threshold auth sessions');
    return new RedisTcpThresholdEd25519AuthSessionStore({ redisUrl, keyPrefix: envPrefix });
  }

  const postgresUrl = getPostgresUrlFromConfig(config);
  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error('[threshold-ecdsa] POSTGRES_URL is set but Postgres is not supported in this runtime');
    }
    input.logger.info('[threshold-ecdsa] Using Postgres store for threshold auth sessions');
    return new PostgresThresholdEd25519AuthSessionStore({ postgresUrl, namespace: envPrefix });
  }

  if (requirePersistent) {
    throw new Error('[threshold-ecdsa] Threshold auth sessions require persistent storage in this runtime; configure UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN or Durable Objects');
  }
  input.logger.info('[threshold-ecdsa] Using in-memory auth session store for threshold sessions (non-persistent)');
  return new InMemoryThresholdEd25519AuthSessionStore({ keyPrefix: envPrefix });
}
