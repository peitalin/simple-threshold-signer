import type { NormalizedLogger } from './logger';
import type { CloudflareDurableObjectNamespaceLike, ThresholdEd25519KeyStoreConfigInput } from './types';
import { THRESHOLD_ED25519_DO_OBJECT_NAME_DEFAULT, THRESHOLD_PREFIX_DEFAULT } from './defaultConfigsServer';
import { isObject as isObjectLoose, toOptionalTrimmedString } from '@shared/utils/validation';
import {
  RedisTcpClient,
  UpstashRedisRestClient,
  redisDel,
  redisGetdelJson,
  redisSetJson,
} from './ThresholdService/kv';
import { getPostgresPool, getPostgresUrlFromConfig } from '../storage/postgres';

export type WebAuthnLoginChallengeRecord = {
  version: 'webauthn_login_challenge_v1';
  challengeId: string;
  userId: string;
  rpId: string;
  challengeB64u: string;
  createdAtMs: number;
  expiresAtMs: number;
};

export interface WebAuthnLoginChallengeStore {
  put(record: WebAuthnLoginChallengeRecord): Promise<void>;
  consume(challengeId: string): Promise<WebAuthnLoginChallengeRecord | null>;
  del(challengeId: string): Promise<void>;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return isObjectLoose(v);
}

function toPrefixWithColon(prefix: unknown, defaultPrefix: string): string {
  const p = toOptionalTrimmedString(prefix);
  if (!p) return defaultPrefix;
  return p.endsWith(':') ? p : `${p}:`;
}

function toWebAuthnLoginChallengePrefix(config: Record<string, unknown>): string {
  const explicit = toOptionalTrimmedString(config.WEBAUTHN_LOGIN_CHALLENGE_PREFIX);
  if (explicit) return toPrefixWithColon(explicit, '');

  const base = toOptionalTrimmedString(config.THRESHOLD_PREFIX) || THRESHOLD_PREFIX_DEFAULT;
  const baseWithColon = toPrefixWithColon(base, `${THRESHOLD_PREFIX_DEFAULT}:`);
  return `${baseWithColon}webauthn:login_challenge:`;
}

function parseWebAuthnLoginChallengeRecord(raw: unknown): WebAuthnLoginChallengeRecord | null {
  if (!isObject(raw)) return null;
  const version = toOptionalTrimmedString(raw.version);
  const challengeId = toOptionalTrimmedString(raw.challengeId);
  const userId = toOptionalTrimmedString(raw.userId);
  const rpId = toOptionalTrimmedString(raw.rpId);
  const challengeB64u = toOptionalTrimmedString(raw.challengeB64u);
  const createdAtMs = typeof raw.createdAtMs === 'number' ? raw.createdAtMs : Number(raw.createdAtMs);
  const expiresAtMs = typeof raw.expiresAtMs === 'number' ? raw.expiresAtMs : Number(raw.expiresAtMs);
  if (version !== 'webauthn_login_challenge_v1') return null;
  if (!challengeId || !userId || !rpId || !challengeB64u) return null;
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) return null;
  return {
    version: 'webauthn_login_challenge_v1',
    challengeId,
    userId,
    rpId,
    challengeB64u,
    createdAtMs: Math.floor(createdAtMs),
    expiresAtMs: Math.floor(expiresAtMs),
  };
}

class InMemoryWebAuthnLoginChallengeStore implements WebAuthnLoginChallengeStore {
  private readonly map = new Map<string, WebAuthnLoginChallengeRecord>();
  private readonly prefix: string;

  constructor(prefix: string) {
    this.prefix = prefix;
  }

  private key(challengeId: string): string {
    return `${this.prefix}${challengeId}`;
  }

  async put(record: WebAuthnLoginChallengeRecord): Promise<void> {
    const parsed = parseWebAuthnLoginChallengeRecord(record);
    if (!parsed) throw new Error('Invalid login challenge record');
    this.map.set(this.key(parsed.challengeId), parsed);
  }

  async consume(challengeId: string): Promise<WebAuthnLoginChallengeRecord | null> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return null;
    const key = this.key(id);
    const rec = this.map.get(key) || null;
    this.map.delete(key);
    if (!rec) return null;
    if (Date.now() > rec.expiresAtMs) return null;
    return rec;
  }

  async del(challengeId: string): Promise<void> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return;
    this.map.delete(this.key(id));
  }
}

class UpstashRedisRestWebAuthnLoginChallengeStore implements WebAuthnLoginChallengeStore {
  private readonly client: UpstashRedisRestClient;
  private readonly prefix: string;

  constructor(input: { url: string; token: string; prefix: string }) {
    this.client = new UpstashRedisRestClient({ url: input.url, token: input.token });
    this.prefix = input.prefix;
  }

  private key(challengeId: string): string {
    return `${this.prefix}${challengeId}`;
  }

  async put(record: WebAuthnLoginChallengeRecord): Promise<void> {
    const parsed = parseWebAuthnLoginChallengeRecord(record);
    if (!parsed) throw new Error('Invalid login challenge record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    await this.client.setJson(this.key(parsed.challengeId), parsed, ttlMs);
  }

  async consume(challengeId: string): Promise<WebAuthnLoginChallengeRecord | null> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return null;
    const raw = await this.client.getdelJson(this.key(id));
    const parsed = parseWebAuthnLoginChallengeRecord(raw);
    if (!parsed) return null;
    if (Date.now() > parsed.expiresAtMs) return null;
    return parsed;
  }

  async del(challengeId: string): Promise<void> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return;
    await this.client.del(this.key(id));
  }
}

class RedisTcpWebAuthnLoginChallengeStore implements WebAuthnLoginChallengeStore {
  private readonly client: RedisTcpClient;
  private readonly prefix: string;

  constructor(input: { redisUrl: string; prefix: string }) {
    this.client = new RedisTcpClient(input.redisUrl);
    this.prefix = input.prefix;
  }

  private key(challengeId: string): string {
    return `${this.prefix}${challengeId}`;
  }

  async put(record: WebAuthnLoginChallengeRecord): Promise<void> {
    const parsed = parseWebAuthnLoginChallengeRecord(record);
    if (!parsed) throw new Error('Invalid login challenge record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    await redisSetJson(this.client, this.key(parsed.challengeId), parsed, ttlMs);
  }

  async consume(challengeId: string): Promise<WebAuthnLoginChallengeRecord | null> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return null;
    const raw = await redisGetdelJson(this.client, this.key(id));
    const parsed = parseWebAuthnLoginChallengeRecord(raw);
    if (!parsed) return null;
    if (Date.now() > parsed.expiresAtMs) return null;
    return parsed;
  }

  async del(challengeId: string): Promise<void> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return;
    await redisDel(this.client, this.key(id));
  }
}

class PostgresWebAuthnLoginChallengeStore implements WebAuthnLoginChallengeStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async put(record: WebAuthnLoginChallengeRecord): Promise<void> {
    const parsed = parseWebAuthnLoginChallengeRecord(record);
    if (!parsed) throw new Error('Invalid login challenge record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO tatchi_webauthn_challenges (namespace, challenge_id, record_json, expires_at_ms)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (namespace, challenge_id)
        DO UPDATE SET record_json = EXCLUDED.record_json, expires_at_ms = EXCLUDED.expires_at_ms
      `,
      [this.namespace, parsed.challengeId, parsed, parsed.expiresAtMs],
    );
  }

  async consume(challengeId: string): Promise<WebAuthnLoginChallengeRecord | null> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return null;
    const pool = await this.poolPromise;
    const nowMs = Date.now();
    const { rows } = await pool.query(
      `
        DELETE FROM tatchi_webauthn_challenges
        WHERE namespace = $1 AND challenge_id = $2 AND expires_at_ms > $3
        RETURNING record_json
      `,
      [this.namespace, id, nowMs],
    );
    const parsed = parseWebAuthnLoginChallengeRecord(rows[0]?.record_json);
    if (!parsed) return null;
    if (Date.now() > parsed.expiresAtMs) return null;
    return parsed;
  }

  async del(challengeId: string): Promise<void> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return;
    const pool = await this.poolPromise;
    await pool.query(
      'DELETE FROM tatchi_webauthn_challenges WHERE namespace = $1 AND challenge_id = $2',
      [this.namespace, id],
    );
  }
}

type DurableObjectStubLike = { fetch(input: RequestInfo, init?: RequestInit): Promise<Response> };
type DoOk<T> = { ok: true; value: T };
type DoErr = { ok: false; code: string; message: string };
type DoResp<T> = DoOk<T> | DoErr;

type DoRequest =
  | { op: 'get'; key: string }
  | { op: 'set'; key: string; value: unknown; ttlMs?: number }
  | { op: 'del'; key: string }
  | { op: 'getdel'; key: string };

function isDurableObjectNamespaceLike(v: unknown): v is CloudflareDurableObjectNamespaceLike {
  return Boolean(v)
    && typeof v === 'object'
    && !Array.isArray(v)
    && typeof (v as CloudflareDurableObjectNamespaceLike).idFromName === 'function'
    && typeof (v as CloudflareDurableObjectNamespaceLike).get === 'function';
}

function resolveDoNamespaceFromConfig(config: Record<string, unknown>): CloudflareDurableObjectNamespaceLike | null {
  const direct = (config as { namespace?: unknown }).namespace;
  if (isDurableObjectNamespaceLike(direct)) return direct;

  const alt = (config as { durableObjectNamespace?: unknown }).durableObjectNamespace;
  if (isDurableObjectNamespaceLike(alt)) return alt;

  const envStyle = (config as { THRESHOLD_ED25519_DO_NAMESPACE?: unknown }).THRESHOLD_ED25519_DO_NAMESPACE;
  if (isDurableObjectNamespaceLike(envStyle)) return envStyle;

  return null;
}

function resolveDoStub(input: { namespace: CloudflareDurableObjectNamespaceLike; objectName: string }): DurableObjectStubLike {
  const id = input.namespace.idFromName(input.objectName);
  return input.namespace.get(id) as unknown as DurableObjectStubLike;
}

async function callDo<T>(stub: DurableObjectStubLike, req: DoRequest): Promise<DoResp<T>> {
  const resp = await stub.fetch('https://threshold-store.invalid/', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(req),
  });
  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(`WebAuthn DO store HTTP ${resp.status}: ${text}`);
  }
  let json: unknown;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`WebAuthn DO store returned non-JSON response: ${text.slice(0, 200)}`);
  }
  if (!isObject(json)) {
    throw new Error('WebAuthn DO store returned invalid JSON shape');
  }
  const ok = (json as { ok?: unknown }).ok;
  if (ok === true) return json as DoOk<T>;
  const code = toOptionalTrimmedString((json as { code?: unknown }).code);
  const message = toOptionalTrimmedString((json as { message?: unknown }).message);
  return { ok: false, code: code || 'internal', message: message || 'WebAuthn DO store error' };
}

class CloudflareDurableObjectWebAuthnLoginChallengeStore implements WebAuthnLoginChallengeStore {
  private readonly stub: DurableObjectStubLike;
  private readonly prefix: string;

  constructor(input: { namespace: CloudflareDurableObjectNamespaceLike; objectName: string; prefix: string }) {
    this.stub = resolveDoStub({ namespace: input.namespace, objectName: input.objectName });
    this.prefix = input.prefix;
  }

  private key(challengeId: string): string {
    return `${this.prefix}${challengeId}`;
  }

  async put(record: WebAuthnLoginChallengeRecord): Promise<void> {
    const parsed = parseWebAuthnLoginChallengeRecord(record);
    if (!parsed) throw new Error('Invalid login challenge record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const resp = await callDo<void>(this.stub, { op: 'set', key: this.key(parsed.challengeId), value: parsed, ttlMs });
    if (!resp.ok) throw new Error(resp.message);
  }

  async consume(challengeId: string): Promise<WebAuthnLoginChallengeRecord | null> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return null;
    const resp = await callDo<unknown | null>(this.stub, { op: 'getdel', key: this.key(id) });
    if (!resp.ok) return null;
    const parsed = parseWebAuthnLoginChallengeRecord(resp.value);
    if (!parsed) return null;
    if (Date.now() > parsed.expiresAtMs) return null;
    return parsed;
  }

  async del(challengeId: string): Promise<void> {
    const id = toOptionalTrimmedString(challengeId);
    if (!id) return;
    const resp = await callDo<void>(this.stub, { op: 'del', key: this.key(id) });
    if (!resp.ok) throw new Error(resp.message);
  }
}

export function createWebAuthnLoginChallengeStore(input: {
  config?: ThresholdEd25519KeyStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): WebAuthnLoginChallengeStore {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const prefix = toWebAuthnLoginChallengePrefix(config);

  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'cloudflare-do') {
    const namespace = resolveDoNamespaceFromConfig(config);
    if (!namespace) {
      throw new Error('cloudflare-do webauthn store selected but no Durable Object namespace was provided (expected config.namespace)');
    }
    const objectName = toOptionalTrimmedString((config as { objectName?: unknown }).objectName)
      || toOptionalTrimmedString((config as { name?: unknown }).name)
      || THRESHOLD_ED25519_DO_OBJECT_NAME_DEFAULT;
    input.logger.info('[webauthn] Using Cloudflare Durable Object store for login challenge persistence');
    return new CloudflareDurableObjectWebAuthnLoginChallengeStore({ namespace, objectName, prefix });
  }

  if (kind === 'in-memory') {
    input.logger.info('[webauthn] Using in-memory login challenge store (non-persistent)');
    return new InMemoryWebAuthnLoginChallengeStore(prefix);
  }

  if (kind === 'upstash-redis-rest') {
    const url = toOptionalTrimmedString(config.url) || toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
    const token = toOptionalTrimmedString(config.token) || toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
    if (!url || !token) {
      throw new Error('Upstash webauthn login challenge store enabled but url/token are not both set');
    }
    input.logger.info('[webauthn] Using Upstash REST login challenge store');
    return new UpstashRedisRestWebAuthnLoginChallengeStore({ url, token, prefix });
  }

  if (kind === 'redis-tcp') {
    if (!input.isNode) {
      input.logger.warn('[webauthn] redis-tcp login challenge store is not supported in this runtime; falling back to in-memory');
      return new InMemoryWebAuthnLoginChallengeStore(prefix);
    }
    const redisUrl = toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL);
    if (!redisUrl) {
      throw new Error('redis-tcp webauthn login challenge store enabled but redisUrl is not set');
    }
    input.logger.info('[webauthn] Using redis-tcp login challenge store');
    return new RedisTcpWebAuthnLoginChallengeStore({ redisUrl, prefix });
  }

  if (kind === 'postgres') {
    if (!input.isNode) {
      throw new Error('[webauthn] postgres login challenge store is not supported in this runtime');
    }
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl) throw new Error('[webauthn] postgres login challenge store enabled but POSTGRES_URL is not set');
    input.logger.info('[webauthn] Using Postgres login challenge store');
    return new PostgresWebAuthnLoginChallengeStore({ postgresUrl, namespace: prefix });
  }

  // Env-shaped config: prefer Redis/Upstash for one-time challenges (TTL + lower Postgres churn).
  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error('Upstash webauthn login challenge store enabled but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set');
    }
    input.logger.info('[webauthn] Using Upstash REST login challenge store');
    return new UpstashRedisRestWebAuthnLoginChallengeStore({ url: upstashUrl, token: upstashToken, prefix });
  }

  const redisUrl = toOptionalTrimmedString(config.REDIS_URL);
  if (redisUrl) {
    if (!input.isNode) {
      input.logger.warn('[webauthn] REDIS_URL is set but TCP Redis is not supported in this runtime; falling back to in-memory');
      return new InMemoryWebAuthnLoginChallengeStore(prefix);
    }
    input.logger.info('[webauthn] Using redis-tcp login challenge store');
    return new RedisTcpWebAuthnLoginChallengeStore({ redisUrl, prefix });
  }

  const postgresUrl = getPostgresUrlFromConfig(config);
  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error('[webauthn] POSTGRES_URL is set but Postgres is not supported in this runtime');
    }
    input.logger.info('[webauthn] Using Postgres login challenge store');
    return new PostgresWebAuthnLoginChallengeStore({ postgresUrl, namespace: prefix });
  }

  input.logger.info('[webauthn] Using in-memory login challenge store (non-persistent)');
  return new InMemoryWebAuthnLoginChallengeStore(prefix);
}
