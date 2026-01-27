import type { NormalizedLogger } from './logger';
import type {
  CloudflareDurableObjectNamespaceLike,
  ThresholdEd25519KeyStoreConfigInput,
} from './types';
import { THRESHOLD_PREFIX_DEFAULT, THRESHOLD_ED25519_DO_OBJECT_NAME_DEFAULT } from './defaultConfigsServer';
import { toOptionalTrimmedString } from '../../utils/validation';
import { isObject as isObjectLoose } from '../../utils/validation';
import {
  RedisTcpClient,
  UpstashRedisRestClient,
  redisDel,
  redisGetJson,
  redisSetJson,
} from './ThresholdService/kv';
import { getPostgresPool, getPostgresUrlFromConfig } from '../storage/postgres';

export type WebAuthnAuthenticatorRecord = {
  version: 'webauthn_authenticator_v1';
  credentialIdB64u: string;
  credentialPublicKeyB64u: string;
  counter: number;
  createdAtMs: number;
  updatedAtMs: number;
};

export interface WebAuthnAuthenticatorStore {
  get(userId: string, credentialIdB64u: string): Promise<WebAuthnAuthenticatorRecord | null>;
  put(userId: string, record: WebAuthnAuthenticatorRecord): Promise<void>;
  del(userId: string, credentialIdB64u: string): Promise<void>;
  /**
   * List all authenticators for a user.
   *
   * Optional because not all backing stores can efficiently enumerate keys.
   */
  list?(userId: string): Promise<WebAuthnAuthenticatorRecord[]>;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return isObjectLoose(v);
}

function toPrefixWithColon(prefix: unknown, defaultPrefix: string): string {
  const p = toOptionalTrimmedString(prefix);
  if (!p) return defaultPrefix;
  return p.endsWith(':') ? p : `${p}:`;
}

function toWebAuthnAuthenticatorPrefix(config: Record<string, unknown>): string {
  const explicit = toOptionalTrimmedString(config.WEBAUTHN_AUTHENTICATOR_PREFIX);
  if (explicit) return toPrefixWithColon(explicit, '');

  const base = toOptionalTrimmedString(config.THRESHOLD_PREFIX) || THRESHOLD_PREFIX_DEFAULT;
  const baseWithColon = toPrefixWithColon(base, `${THRESHOLD_PREFIX_DEFAULT}:`);
  return `${baseWithColon}webauthn:authenticator:`;
}

function parseWebAuthnAuthenticatorRecord(raw: unknown): WebAuthnAuthenticatorRecord | null {
  if (!isObject(raw)) return null;
  const version = toOptionalTrimmedString(raw.version);
  const credentialIdB64u = toOptionalTrimmedString(raw.credentialIdB64u);
  const credentialPublicKeyB64u = toOptionalTrimmedString(raw.credentialPublicKeyB64u);
  const counter = typeof raw.counter === 'number' ? raw.counter : Number(raw.counter);
  const createdAtMs = typeof raw.createdAtMs === 'number' ? raw.createdAtMs : Number(raw.createdAtMs);
  const updatedAtMs = typeof raw.updatedAtMs === 'number' ? raw.updatedAtMs : Number(raw.updatedAtMs);
  if (version !== 'webauthn_authenticator_v1') return null;
  if (!credentialIdB64u || !credentialPublicKeyB64u) return null;
  if (!Number.isFinite(counter) || counter < 0) return null;
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(updatedAtMs) || updatedAtMs <= 0) return null;
  return {
    version: 'webauthn_authenticator_v1',
    credentialIdB64u,
    credentialPublicKeyB64u,
    counter: Math.floor(counter),
    createdAtMs: Math.floor(createdAtMs),
    updatedAtMs: Math.floor(updatedAtMs),
  };
}

class InMemoryWebAuthnAuthenticatorStore implements WebAuthnAuthenticatorStore {
  private readonly map = new Map<string, WebAuthnAuthenticatorRecord>();
  private readonly prefix: string;

  constructor(prefix: string) {
    this.prefix = prefix;
  }

  private key(userId: string, credentialIdB64u: string): string {
    return `${this.prefix}${userId}:${credentialIdB64u}`;
  }

  async get(userId: string, credentialIdB64u: string): Promise<WebAuthnAuthenticatorRecord | null> {
    const uid = toOptionalTrimmedString(userId);
    const cid = toOptionalTrimmedString(credentialIdB64u);
    if (!uid || !cid) return null;
    return this.map.get(this.key(uid, cid)) || null;
  }

  async put(userId: string, record: WebAuthnAuthenticatorRecord): Promise<void> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) throw new Error('Missing userId');
    const parsed = parseWebAuthnAuthenticatorRecord(record);
    if (!parsed) throw new Error('Invalid authenticator record');
    this.map.set(this.key(uid, parsed.credentialIdB64u), parsed);
  }

  async del(userId: string, credentialIdB64u: string): Promise<void> {
    const uid = toOptionalTrimmedString(userId);
    const cid = toOptionalTrimmedString(credentialIdB64u);
    if (!uid || !cid) return;
    this.map.delete(this.key(uid, cid));
  }

  async list(userId: string): Promise<WebAuthnAuthenticatorRecord[]> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) return [];
    const keyPrefix = `${this.prefix}${uid}:`;
    const out: WebAuthnAuthenticatorRecord[] = [];
    for (const [k, v] of this.map.entries()) {
      if (!k.startsWith(keyPrefix)) continue;
      const parsed = parseWebAuthnAuthenticatorRecord(v);
      if (parsed) out.push(parsed);
    }
    out.sort((a, b) => a.createdAtMs - b.createdAtMs);
    return out;
  }
}

class UpstashRedisRestWebAuthnAuthenticatorStore implements WebAuthnAuthenticatorStore {
  private readonly client: UpstashRedisRestClient;
  private readonly prefix: string;

  constructor(input: { url: string; token: string; prefix: string }) {
    this.client = new UpstashRedisRestClient({ url: input.url, token: input.token });
    this.prefix = input.prefix;
  }

  private key(userId: string, credentialIdB64u: string): string {
    return `${this.prefix}${userId}:${credentialIdB64u}`;
  }

  async get(userId: string, credentialIdB64u: string): Promise<WebAuthnAuthenticatorRecord | null> {
    const uid = toOptionalTrimmedString(userId);
    const cid = toOptionalTrimmedString(credentialIdB64u);
    if (!uid || !cid) return null;
    const raw = await this.client.getJson(this.key(uid, cid));
    return parseWebAuthnAuthenticatorRecord(raw);
  }

  async put(userId: string, record: WebAuthnAuthenticatorRecord): Promise<void> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) throw new Error('Missing userId');
    const parsed = parseWebAuthnAuthenticatorRecord(record);
    if (!parsed) throw new Error('Invalid authenticator record');
    await this.client.setJson(this.key(uid, parsed.credentialIdB64u), parsed);
  }

  async del(userId: string, credentialIdB64u: string): Promise<void> {
    const uid = toOptionalTrimmedString(userId);
    const cid = toOptionalTrimmedString(credentialIdB64u);
    if (!uid || !cid) return;
    await this.client.del(this.key(uid, cid));
  }
}

class RedisTcpWebAuthnAuthenticatorStore implements WebAuthnAuthenticatorStore {
  private readonly client: RedisTcpClient;
  private readonly prefix: string;

  constructor(input: { redisUrl: string; prefix: string }) {
    this.client = new RedisTcpClient(input.redisUrl);
    this.prefix = input.prefix;
  }

  private key(userId: string, credentialIdB64u: string): string {
    return `${this.prefix}${userId}:${credentialIdB64u}`;
  }

  async get(userId: string, credentialIdB64u: string): Promise<WebAuthnAuthenticatorRecord | null> {
    const uid = toOptionalTrimmedString(userId);
    const cid = toOptionalTrimmedString(credentialIdB64u);
    if (!uid || !cid) return null;
    const raw = await redisGetJson(this.client, this.key(uid, cid));
    return parseWebAuthnAuthenticatorRecord(raw);
  }

  async put(userId: string, record: WebAuthnAuthenticatorRecord): Promise<void> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) throw new Error('Missing userId');
    const parsed = parseWebAuthnAuthenticatorRecord(record);
    if (!parsed) throw new Error('Invalid authenticator record');
    await redisSetJson(this.client, this.key(uid, parsed.credentialIdB64u), parsed);
  }

  async del(userId: string, credentialIdB64u: string): Promise<void> {
    const uid = toOptionalTrimmedString(userId);
    const cid = toOptionalTrimmedString(credentialIdB64u);
    if (!uid || !cid) return;
    await redisDel(this.client, this.key(uid, cid));
  }
}

type DurableObjectStubLike = { fetch(input: RequestInfo, init?: RequestInit): Promise<Response> };

type DoOk<T> = { ok: true; value: T };
type DoErr = { ok: false; code: string; message: string };
type DoResp<T> = DoOk<T> | DoErr;

type DoGetRequest = { op: 'get'; key: string };
type DoSetRequest = { op: 'set'; key: string; value: unknown; ttlMs?: number };
type DoDelRequest = { op: 'del'; key: string };
type DoRequest =
  | DoGetRequest
  | DoSetRequest
  | DoDelRequest;

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

function resolveDoStub(input: {
  namespace: CloudflareDurableObjectNamespaceLike;
  objectName: string;
}): DurableObjectStubLike {
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

class CloudflareDurableObjectWebAuthnAuthenticatorStore implements WebAuthnAuthenticatorStore {
  private readonly stub: DurableObjectStubLike;
  private readonly prefix: string;

  constructor(input: { namespace: CloudflareDurableObjectNamespaceLike; objectName: string; prefix: string }) {
    this.stub = resolveDoStub({ namespace: input.namespace, objectName: input.objectName });
    this.prefix = input.prefix;
  }

  private key(userId: string, credentialIdB64u: string): string {
    return `${this.prefix}${userId}:${credentialIdB64u}`;
  }

  async get(userId: string, credentialIdB64u: string): Promise<WebAuthnAuthenticatorRecord | null> {
    const uid = toOptionalTrimmedString(userId);
    const cid = toOptionalTrimmedString(credentialIdB64u);
    if (!uid || !cid) return null;
    const resp = await callDo<unknown | null>(this.stub, { op: 'get', key: this.key(uid, cid) });
    if (!resp.ok) return null;
    return parseWebAuthnAuthenticatorRecord(resp.value);
  }

  async put(userId: string, record: WebAuthnAuthenticatorRecord): Promise<void> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) throw new Error('Missing userId');
    const parsed = parseWebAuthnAuthenticatorRecord(record);
    if (!parsed) throw new Error('Invalid authenticator record');
    const resp = await callDo<void>(this.stub, { op: 'set', key: this.key(uid, parsed.credentialIdB64u), value: parsed });
    if (!resp.ok) throw new Error(resp.message);
  }

  async del(userId: string, credentialIdB64u: string): Promise<void> {
    const uid = toOptionalTrimmedString(userId);
    const cid = toOptionalTrimmedString(credentialIdB64u);
    if (!uid || !cid) return;
    const resp = await callDo<void>(this.stub, { op: 'del', key: this.key(uid, cid) });
    if (!resp.ok) throw new Error(resp.message);
  }
}

class PostgresWebAuthnAuthenticatorStore implements WebAuthnAuthenticatorStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async get(userId: string, credentialIdB64u: string): Promise<WebAuthnAuthenticatorRecord | null> {
    const uid = toOptionalTrimmedString(userId);
    const cid = toOptionalTrimmedString(credentialIdB64u);
    if (!uid || !cid) return null;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT credential_public_key_b64u, counter, created_at_ms, updated_at_ms
        FROM tatchi_webauthn_authenticators
        WHERE namespace = $1 AND user_id = $2 AND credential_id_b64u = $3
        LIMIT 1
      `,
      [this.namespace, uid, cid],
    );
    const row = rows[0];
    if (!row) return null;
    const record = {
      version: 'webauthn_authenticator_v1' as const,
      credentialIdB64u: cid,
      credentialPublicKeyB64u: String(row.credential_public_key_b64u ?? ''),
      counter: typeof row.counter === 'number' ? row.counter : Number(row.counter),
      createdAtMs: typeof row.created_at_ms === 'number' ? row.created_at_ms : Number(row.created_at_ms),
      updatedAtMs: typeof row.updated_at_ms === 'number' ? row.updated_at_ms : Number(row.updated_at_ms),
    };
    return parseWebAuthnAuthenticatorRecord(record);
  }

  async put(userId: string, record: WebAuthnAuthenticatorRecord): Promise<void> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) throw new Error('Missing userId');
    const parsed = parseWebAuthnAuthenticatorRecord(record);
    if (!parsed) throw new Error('Invalid authenticator record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO tatchi_webauthn_authenticators (
          namespace, user_id, credential_id_b64u, credential_public_key_b64u, counter, created_at_ms, updated_at_ms
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (namespace, user_id, credential_id_b64u)
        DO UPDATE SET
          credential_public_key_b64u = EXCLUDED.credential_public_key_b64u,
          counter = GREATEST(tatchi_webauthn_authenticators.counter, EXCLUDED.counter),
          created_at_ms = LEAST(tatchi_webauthn_authenticators.created_at_ms, EXCLUDED.created_at_ms),
          updated_at_ms = GREATEST(tatchi_webauthn_authenticators.updated_at_ms, EXCLUDED.updated_at_ms)
      `,
      [
        this.namespace,
        uid,
        parsed.credentialIdB64u,
        parsed.credentialPublicKeyB64u,
        parsed.counter,
        parsed.createdAtMs,
        parsed.updatedAtMs,
      ],
    );
  }

  async del(userId: string, credentialIdB64u: string): Promise<void> {
    const uid = toOptionalTrimmedString(userId);
    const cid = toOptionalTrimmedString(credentialIdB64u);
    if (!uid || !cid) return;
    const pool = await this.poolPromise;
    await pool.query(
      'DELETE FROM tatchi_webauthn_authenticators WHERE namespace = $1 AND user_id = $2 AND credential_id_b64u = $3',
      [this.namespace, uid, cid],
    );
  }

  async list(userId: string): Promise<WebAuthnAuthenticatorRecord[]> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) return [];
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT credential_id_b64u, credential_public_key_b64u, counter, created_at_ms, updated_at_ms
        FROM tatchi_webauthn_authenticators
        WHERE namespace = $1 AND user_id = $2
        ORDER BY created_at_ms ASC
      `,
      [this.namespace, uid],
    );
    const out: WebAuthnAuthenticatorRecord[] = [];
    for (const row of rows || []) {
      const record = parseWebAuthnAuthenticatorRecord({
        version: 'webauthn_authenticator_v1',
        credentialIdB64u: String(row?.credential_id_b64u ?? ''),
        credentialPublicKeyB64u: String(row?.credential_public_key_b64u ?? ''),
        counter: typeof row?.counter === 'number' ? row.counter : Number(row?.counter),
        createdAtMs: typeof row?.created_at_ms === 'number' ? row.created_at_ms : Number(row?.created_at_ms),
        updatedAtMs: typeof row?.updated_at_ms === 'number' ? row.updated_at_ms : Number(row?.updated_at_ms),
      });
      if (record) out.push(record);
    }
    return out;
  }
}

export function createWebAuthnAuthenticatorStore(input: {
  config?: ThresholdEd25519KeyStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): WebAuthnAuthenticatorStore {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const prefix = toWebAuthnAuthenticatorPrefix(config);

  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'cloudflare-do') {
    const namespace = resolveDoNamespaceFromConfig(config);
    if (!namespace) {
      throw new Error('cloudflare-do webauthn store selected but no Durable Object namespace was provided (expected config.namespace)');
    }
    const objectName = toOptionalTrimmedString((config as { objectName?: unknown }).objectName)
      || toOptionalTrimmedString((config as { name?: unknown }).name)
      || THRESHOLD_ED25519_DO_OBJECT_NAME_DEFAULT;
    input.logger.info('[webauthn] Using Cloudflare Durable Object store for authenticator persistence');
    return new CloudflareDurableObjectWebAuthnAuthenticatorStore({ namespace, objectName, prefix });
  }

  if (kind === 'in-memory') {
    input.logger.info('[webauthn] Using in-memory authenticator store (non-persistent)');
    return new InMemoryWebAuthnAuthenticatorStore(prefix);
  }

  if (kind === 'upstash-redis-rest') {
    const url = toOptionalTrimmedString(config.url) || toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
    const token = toOptionalTrimmedString(config.token) || toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
    if (!url || !token) {
      throw new Error('Upstash webauthn store enabled but url/token are not both set');
    }
    input.logger.info('[webauthn] Using Upstash REST authenticator store');
    return new UpstashRedisRestWebAuthnAuthenticatorStore({ url, token, prefix });
  }

  if (kind === 'redis-tcp') {
    if (!input.isNode) {
      input.logger.warn('[webauthn] redis-tcp authenticator store is not supported in this runtime; falling back to in-memory');
      return new InMemoryWebAuthnAuthenticatorStore(prefix);
    }
    const redisUrl = toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL);
    if (!redisUrl) {
      throw new Error('redis-tcp webauthn store enabled but redisUrl is not set');
    }
    input.logger.info('[webauthn] Using redis-tcp authenticator store');
    return new RedisTcpWebAuthnAuthenticatorStore({ redisUrl, prefix });
  }

  if (kind === 'postgres') {
    if (!input.isNode) {
      throw new Error('[webauthn] postgres authenticator store is not supported in this runtime');
    }
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl) throw new Error('[webauthn] postgres authenticator store enabled but POSTGRES_URL is not set');
    input.logger.info('[webauthn] Using Postgres authenticator store');
    return new PostgresWebAuthnAuthenticatorStore({ postgresUrl, namespace: prefix });
  }

  const postgresUrl = getPostgresUrlFromConfig(config);
  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error('[webauthn] POSTGRES_URL is set but Postgres is not supported in this runtime');
    }
    input.logger.info('[webauthn] Using Postgres authenticator store');
    return new PostgresWebAuthnAuthenticatorStore({ postgresUrl, namespace: prefix });
  }

  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error('Upstash webauthn store enabled but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set');
    }
    input.logger.info('[webauthn] Using Upstash REST authenticator store');
    return new UpstashRedisRestWebAuthnAuthenticatorStore({ url: upstashUrl, token: upstashToken, prefix });
  }

  const redisUrl = toOptionalTrimmedString(config.REDIS_URL);
  if (redisUrl) {
    if (!input.isNode) {
      input.logger.warn('[webauthn] REDIS_URL is set but TCP Redis is not supported in this runtime; falling back to in-memory');
      return new InMemoryWebAuthnAuthenticatorStore(prefix);
    }
    input.logger.info('[webauthn] Using redis-tcp authenticator store');
    return new RedisTcpWebAuthnAuthenticatorStore({ redisUrl, prefix });
  }

  input.logger.info('[webauthn] Using in-memory authenticator store (non-persistent)');
  return new InMemoryWebAuthnAuthenticatorStore(prefix);
}
