import type { NormalizedLogger } from './logger';
import type { ThresholdEd25519KeyStoreConfigInput } from './types';
import { THRESHOLD_PREFIX_DEFAULT } from './defaultConfigsServer';
import { isObject as isObjectLoose, toOptionalTrimmedString } from '@shared/utils/validation';
import { RedisTcpClient, UpstashRedisRestClient, redisDel, redisGetJson, redisSetJson } from './ThresholdService/kv';
import { getPostgresPool, getPostgresUrlFromConfig } from '../storage/postgres';

export type DeviceLinkingSessionRecord = {
  version: 'device_linking_session_v1';
  sessionId: string;
  device2PublicKey: string;
  createdAtMs: number;
  expiresAtMs: number;
  claimedAtMs?: number;
  accountId?: string;
  deviceNumber?: number;
  addKeyTxHash?: string;
};

export interface DeviceLinkingSessionStore {
  get(sessionId: string): Promise<DeviceLinkingSessionRecord | null>;
  put(record: DeviceLinkingSessionRecord): Promise<void>;
  del(sessionId: string): Promise<void>;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return isObjectLoose(v);
}

function toPrefixWithColon(prefix: unknown, defaultPrefix: string): string {
  const p = toOptionalTrimmedString(prefix);
  if (!p) return defaultPrefix;
  return p.endsWith(':') ? p : `${p}:`;
}

function toDeviceLinkingSessionPrefix(config: Record<string, unknown>): string {
  const explicit = toOptionalTrimmedString(config.LINK_DEVICE_SESSION_PREFIX);
  if (explicit) return toPrefixWithColon(explicit, '');

  const base = toOptionalTrimmedString(config.THRESHOLD_PREFIX) || THRESHOLD_PREFIX_DEFAULT;
  const baseWithColon = toPrefixWithColon(base, `${THRESHOLD_PREFIX_DEFAULT}:`);
  return `${baseWithColon}device_linking_session:`;
}

function parseDeviceLinkingSessionRecord(raw: unknown): DeviceLinkingSessionRecord | null {
  if (!isObject(raw)) return null;
  const version = toOptionalTrimmedString(raw.version);
  if (version !== 'device_linking_session_v1') return null;

  const sessionId = toOptionalTrimmedString(raw.sessionId);
  const device2PublicKey = toOptionalTrimmedString(raw.device2PublicKey);
  const createdAtMs = typeof raw.createdAtMs === 'number' ? raw.createdAtMs : Number(raw.createdAtMs);
  const expiresAtMs = typeof raw.expiresAtMs === 'number' ? raw.expiresAtMs : Number(raw.expiresAtMs);
  if (!sessionId || !device2PublicKey) return null;
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) return null;

  const claimedAtMs = raw.claimedAtMs == null ? undefined : (typeof raw.claimedAtMs === 'number' ? raw.claimedAtMs : Number(raw.claimedAtMs));
  const accountId = toOptionalTrimmedString(raw.accountId);
  const deviceNumberRaw = raw.deviceNumber == null ? undefined : (typeof raw.deviceNumber === 'number' ? raw.deviceNumber : Number(raw.deviceNumber));
  const deviceNumber = Number.isFinite(deviceNumberRaw as number) && (deviceNumberRaw as number) > 0
    ? Math.floor(deviceNumberRaw as number)
    : undefined;
  const addKeyTxHash = toOptionalTrimmedString(raw.addKeyTxHash);

  const out: DeviceLinkingSessionRecord = {
    version: 'device_linking_session_v1',
    sessionId,
    device2PublicKey,
    createdAtMs: Math.floor(createdAtMs),
    expiresAtMs: Math.floor(expiresAtMs),
    ...(Number.isFinite(claimedAtMs) && claimedAtMs! > 0 ? { claimedAtMs: Math.floor(claimedAtMs!) } : {}),
    ...(accountId ? { accountId } : {}),
    ...(deviceNumber ? { deviceNumber } : {}),
    ...(addKeyTxHash ? { addKeyTxHash } : {}),
  };

  return out;
}

class InMemoryDeviceLinkingSessionStore implements DeviceLinkingSessionStore {
  private readonly namespace: string;
  private readonly map = new Map<string, DeviceLinkingSessionRecord>();

  constructor(input: { namespace: string }) {
    this.namespace = input.namespace;
  }

  private key(sessionId: string): string {
    return `${this.namespace}${sessionId}`;
  }

  async get(sessionId: string): Promise<DeviceLinkingSessionRecord | null> {
    const id = toOptionalTrimmedString(sessionId);
    if (!id) return null;
    const rec = this.map.get(this.key(id));
    const parsed = parseDeviceLinkingSessionRecord(rec);
    if (!parsed) return null;
    if (Date.now() > parsed.expiresAtMs) {
      this.map.delete(this.key(id));
      return null;
    }
    return parsed;
  }

  async put(record: DeviceLinkingSessionRecord): Promise<void> {
    const parsed = parseDeviceLinkingSessionRecord(record);
    if (!parsed) throw new Error('Invalid device linking session record');
    this.map.set(this.key(parsed.sessionId), parsed);
  }

  async del(sessionId: string): Promise<void> {
    const id = toOptionalTrimmedString(sessionId);
    if (!id) return;
    this.map.delete(this.key(id));
  }
}

class PostgresDeviceLinkingSessionStore implements DeviceLinkingSessionStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async get(sessionId: string): Promise<DeviceLinkingSessionRecord | null> {
    const id = toOptionalTrimmedString(sessionId);
    if (!id) return null;
    const pool = await this.poolPromise;
    const nowMs = Date.now();
    const { rows } = await pool.query(
      `
        SELECT record_json
        FROM device_linking_sessions
        WHERE namespace = $1 AND session_id = $2 AND expires_at_ms > $3
      `,
      [this.namespace, id, nowMs],
    );
    const parsed = parseDeviceLinkingSessionRecord(rows[0]?.record_json);
    if (!parsed) return null;
    if (Date.now() > parsed.expiresAtMs) return null;
    return parsed;
  }

  async put(record: DeviceLinkingSessionRecord): Promise<void> {
    const parsed = parseDeviceLinkingSessionRecord(record);
    if (!parsed) throw new Error('Invalid device linking session record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO device_linking_sessions (namespace, session_id, record_json, expires_at_ms)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (namespace, session_id)
        DO UPDATE SET record_json = EXCLUDED.record_json, expires_at_ms = EXCLUDED.expires_at_ms
      `,
      [this.namespace, parsed.sessionId, parsed, parsed.expiresAtMs],
    );
  }

  async del(sessionId: string): Promise<void> {
    const id = toOptionalTrimmedString(sessionId);
    if (!id) return;
    const pool = await this.poolPromise;
    await pool.query(
      'DELETE FROM device_linking_sessions WHERE namespace = $1 AND session_id = $2',
      [this.namespace, id],
    );
  }
}

class UpstashRedisRestDeviceLinkingSessionStore implements DeviceLinkingSessionStore {
  private readonly client: UpstashRedisRestClient;
  private readonly prefix: string;

  constructor(input: { url: string; token: string; prefix: string }) {
    this.client = new UpstashRedisRestClient({ url: input.url, token: input.token });
    this.prefix = input.prefix;
  }

  private key(sessionId: string): string {
    return `${this.prefix}${sessionId}`;
  }

  async get(sessionId: string): Promise<DeviceLinkingSessionRecord | null> {
    const id = toOptionalTrimmedString(sessionId);
    if (!id) return null;
    const raw = await this.client.getJson(this.key(id));
    const parsed = parseDeviceLinkingSessionRecord(raw);
    if (!parsed) return null;
    if (Date.now() > parsed.expiresAtMs) {
      await this.del(id);
      return null;
    }
    return parsed;
  }

  async put(record: DeviceLinkingSessionRecord): Promise<void> {
    const parsed = parseDeviceLinkingSessionRecord(record);
    if (!parsed) throw new Error('Invalid device linking session record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    await this.client.setJson(this.key(parsed.sessionId), parsed, ttlMs);
  }

  async del(sessionId: string): Promise<void> {
    const id = toOptionalTrimmedString(sessionId);
    if (!id) return;
    await this.client.del(this.key(id));
  }
}

class RedisTcpDeviceLinkingSessionStore implements DeviceLinkingSessionStore {
  private readonly client: RedisTcpClient;
  private readonly prefix: string;

  constructor(input: { redisUrl: string; prefix: string }) {
    this.client = new RedisTcpClient(input.redisUrl);
    this.prefix = input.prefix;
  }

  private key(sessionId: string): string {
    return `${this.prefix}${sessionId}`;
  }

  async get(sessionId: string): Promise<DeviceLinkingSessionRecord | null> {
    const id = toOptionalTrimmedString(sessionId);
    if (!id) return null;
    const raw = await redisGetJson(this.client, this.key(id));
    const parsed = parseDeviceLinkingSessionRecord(raw);
    if (!parsed) return null;
    if (Date.now() > parsed.expiresAtMs) {
      await this.del(id);
      return null;
    }
    return parsed;
  }

  async put(record: DeviceLinkingSessionRecord): Promise<void> {
    const parsed = parseDeviceLinkingSessionRecord(record);
    if (!parsed) throw new Error('Invalid device linking session record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    await redisSetJson(this.client, this.key(parsed.sessionId), parsed, ttlMs);
  }

  async del(sessionId: string): Promise<void> {
    const id = toOptionalTrimmedString(sessionId);
    if (!id) return;
    await redisDel(this.client, this.key(id));
  }
}

export function createDeviceLinkingSessionStore(input: {
  config?: ThresholdEd25519KeyStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): DeviceLinkingSessionStore {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const namespace = toDeviceLinkingSessionPrefix(config);
  const allowInMemory = toOptionalTrimmedString(config.THRESHOLD_ALLOW_IN_MEMORY_STORES) === '1';
  const requirePersistent = !input.isNode && !allowInMemory;

  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'in-memory') {
    if (requirePersistent) {
      throw new Error('[link-device] In-memory session store is not supported in this runtime; configure Upstash/Redis');
    }
    input.logger.info('[link-device] Using in-memory session store (non-persistent)');
    return new InMemoryDeviceLinkingSessionStore({ namespace });
  }
  if (kind === 'upstash-redis-rest') {
    const url = toOptionalTrimmedString(config.url) || toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
    const token = toOptionalTrimmedString(config.token) || toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
    if (!url || !token) {
      throw new Error('[link-device] upstash-redis-rest session store enabled but url/token are not both set');
    }
    input.logger.info('[link-device] Using Upstash REST session store');
    return new UpstashRedisRestDeviceLinkingSessionStore({ url, token, prefix: namespace });
  }
  if (kind === 'redis-tcp') {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error('[link-device] redis-tcp session store is not supported in this runtime; configure Upstash/Redis REST');
      }
      input.logger.warn('[link-device] redis-tcp session store is not supported in this runtime; falling back to in-memory');
      return new InMemoryDeviceLinkingSessionStore({ namespace });
    }
    const redisUrl = toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL);
    if (!redisUrl) throw new Error('[link-device] redis-tcp session store enabled but REDIS_URL is not set');
    input.logger.info('[link-device] Using redis-tcp session store');
    return new RedisTcpDeviceLinkingSessionStore({ redisUrl, prefix: namespace });
  }
  if (kind === 'postgres') {
    if (!input.isNode) throw new Error('[link-device] postgres session store is not supported in this runtime');
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl) throw new Error('[link-device] postgres session store enabled but POSTGRES_URL is not set');
    input.logger.info('[link-device] Using Postgres session store');
    return new PostgresDeviceLinkingSessionStore({ postgresUrl, namespace });
  }

  // Env-shaped config: prefer Redis/Upstash for session storage (TTL + lower Postgres churn).
  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error('[link-device] Upstash session store enabled but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set');
    }
    input.logger.info('[link-device] Using Upstash REST session store');
    return new UpstashRedisRestDeviceLinkingSessionStore({ url: upstashUrl, token: upstashToken, prefix: namespace });
  }

  const redisUrl = toOptionalTrimmedString(config.REDIS_URL);
  if (redisUrl) {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error('[link-device] REDIS_URL is set but TCP Redis is not supported in this runtime; use Upstash/Redis REST');
      }
      input.logger.warn('[link-device] REDIS_URL is set but TCP Redis is not supported in this runtime; falling back to in-memory');
      return new InMemoryDeviceLinkingSessionStore({ namespace });
    }
    input.logger.info('[link-device] Using redis-tcp session store');
    return new RedisTcpDeviceLinkingSessionStore({ redisUrl, prefix: namespace });
  }

  const postgresUrl = getPostgresUrlFromConfig(config);
  if (postgresUrl) {
    if (!input.isNode) throw new Error('[link-device] POSTGRES_URL is set but Postgres is not supported in this runtime');
    input.logger.info('[link-device] Using Postgres session store');
    return new PostgresDeviceLinkingSessionStore({ postgresUrl, namespace });
  }

  if (requirePersistent) {
    throw new Error('[link-device] Device linking sessions require persistent storage in this runtime; configure UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN');
  }

  input.logger.info('[link-device] Using in-memory session store (non-persistent)');
  return new InMemoryDeviceLinkingSessionStore({ namespace });
}
