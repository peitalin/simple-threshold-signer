import type { NormalizedLogger } from './logger';
import type { CloudflareDurableObjectNamespaceLike, ThresholdEd25519KeyStoreConfigInput } from './types';
import { THRESHOLD_ED25519_DO_OBJECT_NAME_DEFAULT, THRESHOLD_PREFIX_DEFAULT } from './defaultConfigsServer';
import { base64UrlEncode } from '@shared/utils/encoders';
import { isObject as isObjectLoose, toOptionalTrimmedString } from '@shared/utils/validation';
import { RedisTcpClient, UpstashRedisRestClient, redisDel, redisGetJson, redisSetJson } from './ThresholdService/kv';
import { getPostgresPool, getPostgresUrlFromConfig } from '../storage/postgres';

export type IdentitySubjectRecord = {
  version: 'identity_subject_v1';
  subject: string;
  userId: string;
  createdAtMs: number;
  updatedAtMs: number;
};

export type IdentityUserRecord = {
  version: 'identity_user_v1';
  userId: string;
  subjects: string[];
  createdAtMs: number;
  updatedAtMs: number;
};

export type AppSessionVersionRecord = {
  version: 'app_session_version_v1';
  userId: string;
  appSessionVersion: string;
  createdAtMs: number;
  updatedAtMs: number;
};

export type LinkIdentityResult =
  | { ok: true; movedFromUserId?: string }
  | { ok: false; code: string; message: string };

export type UnlinkIdentityResult =
  | { ok: true }
  | { ok: false; code: string; message: string };

export interface IdentityStore {
  getUserIdBySubject(subject: string): Promise<string | null>;
  listSubjectsByUserId(userId: string): Promise<string[]>;
  linkSubjectToUserId(input: { userId: string; subject: string; allowMoveIfSoleIdentity?: boolean }): Promise<LinkIdentityResult>;
  unlinkSubjectFromUserId(input: { userId: string; subject: string }): Promise<UnlinkIdentityResult>;

  /**
   * Returns the current app session version for a user.
   * This enables server-side revocation of otherwise stateless JWT sessions.
   */
  getAppSessionVersionByUserId(userId: string): Promise<string | null>;
  /**
   * Returns the current app session version or creates one if missing.
   */
  ensureAppSessionVersionByUserId(userId: string): Promise<string>;
  /**
   * Rotates the app session version and returns the new value.
   * Any existing app-session JWTs with the previous version become invalid.
   */
  rotateAppSessionVersionByUserId(userId: string): Promise<string>;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return isObjectLoose(v);
}

function toPrefixWithColon(prefix: unknown, defaultPrefix: string): string {
  const p = toOptionalTrimmedString(prefix);
  if (!p) return defaultPrefix;
  return p.endsWith(':') ? p : `${p}:`;
}

function toIdentityPrefix(config: Record<string, unknown>): string {
  const explicit = toOptionalTrimmedString(config.IDENTITY_PREFIX) || toOptionalTrimmedString(config.IDENTITY_MAP_PREFIX);
  if (explicit) return toPrefixWithColon(explicit, '');

  const base = toOptionalTrimmedString(config.THRESHOLD_PREFIX) || THRESHOLD_PREFIX_DEFAULT;
  const baseWithColon = toPrefixWithColon(base, `${THRESHOLD_PREFIX_DEFAULT}:`);
  return `${baseWithColon}identity:`;
}

function generateAppSessionVersion(): string {
  const bytes = new Uint8Array(16);
  try {
    globalThis.crypto.getRandomValues(bytes);
  } catch {
    for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  return base64UrlEncode(bytes);
}

function parseIdentitySubjectRecord(raw: unknown): IdentitySubjectRecord | null {
  if (!isObject(raw)) return null;
  const version = toOptionalTrimmedString(raw.version);
  const subject = toOptionalTrimmedString(raw.subject);
  const userId = toOptionalTrimmedString(raw.userId);
  const createdAtMsRaw = (raw as { createdAtMs?: unknown }).createdAtMs;
  const updatedAtMsRaw = (raw as { updatedAtMs?: unknown }).updatedAtMs;
  const createdAtMs = typeof createdAtMsRaw === 'number' ? createdAtMsRaw : Number(createdAtMsRaw);
  const updatedAtMs = typeof updatedAtMsRaw === 'number' ? updatedAtMsRaw : Number(updatedAtMsRaw);
  if (version !== 'identity_subject_v1') return null;
  if (!subject || !userId) return null;
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(updatedAtMs) || updatedAtMs <= 0) return null;
  return {
    version: 'identity_subject_v1',
    subject,
    userId,
    createdAtMs: Math.floor(createdAtMs),
    updatedAtMs: Math.floor(updatedAtMs),
  };
}

function parseIdentityUserRecord(raw: unknown): IdentityUserRecord | null {
  if (!isObject(raw)) return null;
  const version = toOptionalTrimmedString(raw.version);
  const userId = toOptionalTrimmedString(raw.userId);
  const subjectsRaw = (raw as { subjects?: unknown }).subjects;
  const subjects = Array.isArray(subjectsRaw)
    ? subjectsRaw.map((s) => (typeof s === 'string' ? s.trim() : '')).filter(Boolean)
    : null;
  const createdAtMsRaw = (raw as { createdAtMs?: unknown }).createdAtMs;
  const updatedAtMsRaw = (raw as { updatedAtMs?: unknown }).updatedAtMs;
  const createdAtMs = typeof createdAtMsRaw === 'number' ? createdAtMsRaw : Number(createdAtMsRaw);
  const updatedAtMs = typeof updatedAtMsRaw === 'number' ? updatedAtMsRaw : Number(updatedAtMsRaw);
  if (version !== 'identity_user_v1') return null;
  if (!userId || !subjects) return null;
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(updatedAtMs) || updatedAtMs <= 0) return null;
  const uniqueSubjects = Array.from(new Set(subjects));
  uniqueSubjects.sort();
  return {
    version: 'identity_user_v1',
    userId,
    subjects: uniqueSubjects,
    createdAtMs: Math.floor(createdAtMs),
    updatedAtMs: Math.floor(updatedAtMs),
  };
}

function parseAppSessionVersionRecord(raw: unknown): AppSessionVersionRecord | null {
  if (!isObject(raw)) return null;
  const version = toOptionalTrimmedString(raw.version);
  const userId = toOptionalTrimmedString(raw.userId);
  const appSessionVersion = toOptionalTrimmedString(raw.appSessionVersion);
  const createdAtMsRaw = (raw as { createdAtMs?: unknown }).createdAtMs;
  const updatedAtMsRaw = (raw as { updatedAtMs?: unknown }).updatedAtMs;
  const createdAtMs = typeof createdAtMsRaw === 'number' ? createdAtMsRaw : Number(createdAtMsRaw);
  const updatedAtMs = typeof updatedAtMsRaw === 'number' ? updatedAtMsRaw : Number(updatedAtMsRaw);
  if (version !== 'app_session_version_v1') return null;
  if (!userId || !appSessionVersion) return null;
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(updatedAtMs) || updatedAtMs <= 0) return null;
  return {
    version: 'app_session_version_v1',
    userId,
    appSessionVersion,
    createdAtMs: Math.floor(createdAtMs),
    updatedAtMs: Math.floor(updatedAtMs),
  };
}

class InMemoryIdentityStore implements IdentityStore {
  private readonly prefix: string;
  private readonly subjectToUser = new Map<string, IdentitySubjectRecord>();
  private readonly userToSubjects = new Map<string, IdentityUserRecord>();
  private readonly userToAppSessionVersion = new Map<string, AppSessionVersionRecord>();

  constructor(prefix: string) {
    this.prefix = prefix;
  }

  private subjectKey(subject: string): string {
    return `${this.prefix}subject:${subject}`;
  }

  private userKey(userId: string): string {
    return `${this.prefix}user:${userId}`;
  }

  private appSessionVersionKey(userId: string): string {
    return `${this.prefix}app_session_version:${userId}`;
  }

  async getUserIdBySubject(subject: string): Promise<string | null> {
    const s = toOptionalTrimmedString(subject);
    if (!s) return null;
    return this.subjectToUser.get(this.subjectKey(s))?.userId || null;
  }

  async listSubjectsByUserId(userId: string): Promise<string[]> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) return [];
    return this.userToSubjects.get(this.userKey(uid))?.subjects || [];
  }

  async linkSubjectToUserId(input: {
    userId: string;
    subject: string;
    allowMoveIfSoleIdentity?: boolean;
  }): Promise<LinkIdentityResult> {
    const userId = toOptionalTrimmedString(input.userId);
    const subject = toOptionalTrimmedString(input.subject);
    if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
    if (!subject) return { ok: false, code: 'invalid_args', message: 'Missing subject' };

    const now = Date.now();
    const existing = this.subjectToUser.get(this.subjectKey(subject)) || null;
    if (existing && existing.userId !== userId) {
      if (!input.allowMoveIfSoleIdentity) {
        return { ok: false, code: 'already_linked', message: 'Subject is already linked to a different user' };
      }
      const sourceUser = existing.userId;
      const source = this.userToSubjects.get(this.userKey(sourceUser)) || null;
      const sourceSubjects = source?.subjects || [];
      if (sourceSubjects.length !== 1 || sourceSubjects[0] !== subject) {
        return {
          ok: false,
          code: 'already_linked',
          message: 'Subject is linked to a different user with other identities; merge is not allowed',
        };
      }
      this.userToSubjects.set(this.userKey(sourceUser), {
        version: 'identity_user_v1',
        userId: sourceUser,
        subjects: [],
        createdAtMs: source?.createdAtMs || now,
        updatedAtMs: now,
      });
      this.subjectToUser.set(this.subjectKey(subject), {
        version: 'identity_subject_v1',
        subject,
        userId,
        createdAtMs: existing.createdAtMs,
        updatedAtMs: now,
      });

      const dest = this.userToSubjects.get(this.userKey(userId)) || null;
      const destSubjects = Array.from(new Set([...(dest?.subjects || []), subject]));
      destSubjects.sort();
      this.userToSubjects.set(this.userKey(userId), {
        version: 'identity_user_v1',
        userId,
        subjects: destSubjects,
        createdAtMs: dest?.createdAtMs || now,
        updatedAtMs: now,
      });
      return { ok: true, movedFromUserId: sourceUser };
    }

    if (!existing) {
      this.subjectToUser.set(this.subjectKey(subject), {
        version: 'identity_subject_v1',
        subject,
        userId,
        createdAtMs: now,
        updatedAtMs: now,
      });
    } else {
      this.subjectToUser.set(this.subjectKey(subject), { ...existing, updatedAtMs: now });
    }

    const existingUser = this.userToSubjects.get(this.userKey(userId)) || null;
    const nextSubjects = Array.from(new Set([...(existingUser?.subjects || []), subject]));
    nextSubjects.sort();
    this.userToSubjects.set(this.userKey(userId), {
      version: 'identity_user_v1',
      userId,
      subjects: nextSubjects,
      createdAtMs: existingUser?.createdAtMs || now,
      updatedAtMs: now,
    });
    return { ok: true };
  }

  async unlinkSubjectFromUserId(input: { userId: string; subject: string }): Promise<UnlinkIdentityResult> {
    const userId = toOptionalTrimmedString(input.userId);
    const subject = toOptionalTrimmedString(input.subject);
    if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
    if (!subject) return { ok: false, code: 'invalid_args', message: 'Missing subject' };

    const existing = this.subjectToUser.get(this.subjectKey(subject)) || null;
    if (!existing || existing.userId !== userId) {
      return { ok: false, code: 'not_found', message: 'Subject is not linked to this user' };
    }

    const userRec = this.userToSubjects.get(this.userKey(userId)) || null;
    const subjects = userRec?.subjects || [];
    if (subjects.length <= 1) {
      return { ok: false, code: 'cannot_unlink_last_identity', message: 'Refusing to remove the last remaining identity' };
    }

    this.subjectToUser.delete(this.subjectKey(subject));
    const now = Date.now();
    const nextSubjects = subjects.filter((s) => s !== subject);
    nextSubjects.sort();
    this.userToSubjects.set(this.userKey(userId), {
      version: 'identity_user_v1',
      userId,
      subjects: nextSubjects,
      createdAtMs: userRec?.createdAtMs || now,
      updatedAtMs: now,
    });

    return { ok: true };
  }

  async getAppSessionVersionByUserId(userId: string): Promise<string | null> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) return null;
    return this.userToAppSessionVersion.get(this.appSessionVersionKey(uid))?.appSessionVersion || null;
  }

  async ensureAppSessionVersionByUserId(userId: string): Promise<string> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) throw new Error('Missing userId');
    const existing = this.userToAppSessionVersion.get(this.appSessionVersionKey(uid)) || null;
    if (existing?.appSessionVersion) return existing.appSessionVersion;

    const now = Date.now();
    const appSessionVersion = generateAppSessionVersion();
    const record: AppSessionVersionRecord = {
      version: 'app_session_version_v1',
      userId: uid,
      appSessionVersion,
      createdAtMs: now,
      updatedAtMs: now,
    };
    this.userToAppSessionVersion.set(this.appSessionVersionKey(uid), record);
    return appSessionVersion;
  }

  async rotateAppSessionVersionByUserId(userId: string): Promise<string> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) throw new Error('Missing userId');
    const existing = this.userToAppSessionVersion.get(this.appSessionVersionKey(uid)) || null;
    const now = Date.now();
    const appSessionVersion = generateAppSessionVersion();
    const record: AppSessionVersionRecord = {
      version: 'app_session_version_v1',
      userId: uid,
      appSessionVersion,
      createdAtMs: existing?.createdAtMs || now,
      updatedAtMs: now,
    };
    this.userToAppSessionVersion.set(this.appSessionVersionKey(uid), record);
    return appSessionVersion;
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
    throw new Error(`Identity DO store HTTP ${resp.status}: ${text}`);
  }
  let json: unknown;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`Identity DO store returned non-JSON response: ${text.slice(0, 200)}`);
  }
  if (!isObject(json)) {
    throw new Error('Identity DO store returned invalid JSON shape');
  }
  const ok = (json as { ok?: unknown }).ok;
  if (ok === true) return json as DoOk<T>;
  const code = toOptionalTrimmedString((json as { code?: unknown }).code);
  const message = toOptionalTrimmedString((json as { message?: unknown }).message);
  return { ok: false, code: code || 'internal', message: message || 'Identity DO store error' };
}

abstract class KvBackedIdentityStore implements IdentityStore {
  protected readonly prefix: string;

  constructor(prefix: string) {
    this.prefix = prefix;
  }

  protected subjectKey(subject: string): string {
    return `${this.prefix}subject:${subject}`;
  }

  protected userKey(userId: string): string {
    return `${this.prefix}user:${userId}`;
  }

  protected appSessionVersionKey(userId: string): string {
    return `${this.prefix}app_session_version:${userId}`;
  }

  protected abstract getJson(key: string): Promise<unknown | null>;
  protected abstract setJson(key: string, value: unknown): Promise<void>;
  protected abstract del(key: string): Promise<void>;

  async getUserIdBySubject(subject: string): Promise<string | null> {
    const s = toOptionalTrimmedString(subject);
    if (!s) return null;
    const raw = await this.getJson(this.subjectKey(s));
    const parsed = parseIdentitySubjectRecord(raw);
    return parsed?.userId || null;
  }

  async listSubjectsByUserId(userId: string): Promise<string[]> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) return [];
    const raw = await this.getJson(this.userKey(uid));
    const parsed = parseIdentityUserRecord(raw);
    return parsed?.subjects || [];
  }

  async linkSubjectToUserId(input: {
    userId: string;
    subject: string;
    allowMoveIfSoleIdentity?: boolean;
  }): Promise<LinkIdentityResult> {
    const userId = toOptionalTrimmedString(input.userId);
    const subject = toOptionalTrimmedString(input.subject);
    if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
    if (!subject) return { ok: false, code: 'invalid_args', message: 'Missing subject' };

    const now = Date.now();
    const existingSubject = parseIdentitySubjectRecord(await this.getJson(this.subjectKey(subject)));
    if (existingSubject && existingSubject.userId !== userId) {
      if (!input.allowMoveIfSoleIdentity) {
        return { ok: false, code: 'already_linked', message: 'Subject is already linked to a different user' };
      }
      const sourceUser = existingSubject.userId;
      const sourceUserRec = parseIdentityUserRecord(await this.getJson(this.userKey(sourceUser)));
      const sourceSubjects = sourceUserRec?.subjects || [];
      if (sourceSubjects.length !== 1 || sourceSubjects[0] !== subject) {
        return {
          ok: false,
          code: 'already_linked',
          message: 'Subject is linked to a different user with other identities; merge is not allowed',
        };
      }

      const destUserRec = parseIdentityUserRecord(await this.getJson(this.userKey(userId)));
      const destSubjects = Array.from(new Set([...(destUserRec?.subjects || []), subject]));
      destSubjects.sort();
      await this.setJson(this.userKey(userId), {
        version: 'identity_user_v1',
        userId,
        subjects: destSubjects,
        createdAtMs: destUserRec?.createdAtMs || now,
        updatedAtMs: now,
      } satisfies IdentityUserRecord);

      await this.setJson(this.userKey(sourceUser), {
        version: 'identity_user_v1',
        userId: sourceUser,
        subjects: [],
        createdAtMs: sourceUserRec?.createdAtMs || existingSubject.createdAtMs || now,
        updatedAtMs: now,
      } satisfies IdentityUserRecord);

      await this.setJson(this.subjectKey(subject), {
        version: 'identity_subject_v1',
        subject,
        userId,
        createdAtMs: existingSubject.createdAtMs || now,
        updatedAtMs: now,
      } satisfies IdentitySubjectRecord);

      return { ok: true, movedFromUserId: sourceUser };
    }

    await this.setJson(this.subjectKey(subject), {
      version: 'identity_subject_v1',
      subject,
      userId,
      createdAtMs: existingSubject?.createdAtMs || now,
      updatedAtMs: now,
    } satisfies IdentitySubjectRecord);

    const userRec = parseIdentityUserRecord(await this.getJson(this.userKey(userId)));
    const subjects = Array.from(new Set([...(userRec?.subjects || []), subject]));
    subjects.sort();
    await this.setJson(this.userKey(userId), {
      version: 'identity_user_v1',
      userId,
      subjects,
      createdAtMs: userRec?.createdAtMs || now,
      updatedAtMs: now,
    } satisfies IdentityUserRecord);
    return { ok: true };
  }

  async unlinkSubjectFromUserId(input: { userId: string; subject: string }): Promise<UnlinkIdentityResult> {
    const userId = toOptionalTrimmedString(input.userId);
    const subject = toOptionalTrimmedString(input.subject);
    if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
    if (!subject) return { ok: false, code: 'invalid_args', message: 'Missing subject' };

    const subjectRec = parseIdentitySubjectRecord(await this.getJson(this.subjectKey(subject)));
    if (!subjectRec || subjectRec.userId !== userId) {
      return { ok: false, code: 'not_found', message: 'Subject is not linked to this user' };
    }

    const userRec = parseIdentityUserRecord(await this.getJson(this.userKey(userId)));
    const subjects = userRec?.subjects || [];
    if (subjects.length <= 1) {
      return { ok: false, code: 'cannot_unlink_last_identity', message: 'Refusing to remove the last remaining identity' };
    }

    const nextSubjects = subjects.filter((s) => s !== subject);
    nextSubjects.sort();
    await this.setJson(this.userKey(userId), {
      version: 'identity_user_v1',
      userId,
      subjects: nextSubjects,
      createdAtMs: userRec?.createdAtMs || Date.now(),
      updatedAtMs: Date.now(),
    } satisfies IdentityUserRecord);
    await this.del(this.subjectKey(subject));
    return { ok: true };
  }

  async getAppSessionVersionByUserId(userId: string): Promise<string | null> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) return null;
    const raw = await this.getJson(this.appSessionVersionKey(uid));
    const parsed = parseAppSessionVersionRecord(raw);
    return parsed?.appSessionVersion || null;
  }

  async ensureAppSessionVersionByUserId(userId: string): Promise<string> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) throw new Error('Missing userId');

    const existing = parseAppSessionVersionRecord(await this.getJson(this.appSessionVersionKey(uid)));
    if (existing?.appSessionVersion) return existing.appSessionVersion;

    const now = Date.now();
    const appSessionVersion = generateAppSessionVersion();
    await this.setJson(this.appSessionVersionKey(uid), {
      version: 'app_session_version_v1',
      userId: uid,
      appSessionVersion,
      createdAtMs: now,
      updatedAtMs: now,
    } satisfies AppSessionVersionRecord);

    const reread = parseAppSessionVersionRecord(await this.getJson(this.appSessionVersionKey(uid)));
    return reread?.appSessionVersion || appSessionVersion;
  }

  async rotateAppSessionVersionByUserId(userId: string): Promise<string> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) throw new Error('Missing userId');

    const existing = parseAppSessionVersionRecord(await this.getJson(this.appSessionVersionKey(uid)));
    const now = Date.now();
    const appSessionVersion = generateAppSessionVersion();
    await this.setJson(this.appSessionVersionKey(uid), {
      version: 'app_session_version_v1',
      userId: uid,
      appSessionVersion,
      createdAtMs: existing?.createdAtMs || now,
      updatedAtMs: now,
    } satisfies AppSessionVersionRecord);
    return appSessionVersion;
  }
}

class UpstashRedisRestIdentityStore extends KvBackedIdentityStore {
  private readonly client: UpstashRedisRestClient;

  constructor(input: { url: string; token: string; prefix: string }) {
    super(input.prefix);
    this.client = new UpstashRedisRestClient({ url: input.url, token: input.token });
  }

  protected getJson(key: string): Promise<unknown | null> {
    return this.client.getJson(key);
  }
  protected setJson(key: string, value: unknown): Promise<void> {
    return this.client.setJson(key, value);
  }
  protected del(key: string): Promise<void> {
    return this.client.del(key);
  }
}

class RedisTcpIdentityStore extends KvBackedIdentityStore {
  private readonly client: RedisTcpClient;

  constructor(input: { redisUrl: string; prefix: string }) {
    super(input.prefix);
    this.client = new RedisTcpClient(input.redisUrl);
  }

  protected getJson(key: string): Promise<unknown | null> {
    return redisGetJson(this.client, key);
  }
  protected setJson(key: string, value: unknown): Promise<void> {
    return redisSetJson(this.client, key, value);
  }
  protected del(key: string): Promise<void> {
    return redisDel(this.client, key);
  }
}

class CloudflareDurableObjectIdentityStore extends KvBackedIdentityStore {
  private readonly stub: DurableObjectStubLike;

  constructor(input: { namespace: CloudflareDurableObjectNamespaceLike; objectName: string; prefix: string }) {
    super(input.prefix);
    this.stub = resolveDoStub({ namespace: input.namespace, objectName: input.objectName });
  }

  protected async getJson(key: string): Promise<unknown | null> {
    const resp = await callDo<unknown | null>(this.stub, { op: 'get', key });
    if (!resp.ok) return null;
    return resp.value;
  }
  protected async setJson(key: string, value: unknown): Promise<void> {
    const resp = await callDo<void>(this.stub, { op: 'set', key, value });
    if (!resp.ok) throw new Error(resp.message);
  }
  protected async del(key: string): Promise<void> {
    const resp = await callDo<void>(this.stub, { op: 'del', key });
    if (!resp.ok) throw new Error(resp.message);
  }
}

class PostgresIdentityStore implements IdentityStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async getUserIdBySubject(subject: string): Promise<string | null> {
    const s = toOptionalTrimmedString(subject);
    if (!s) return null;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      'SELECT user_id FROM identity_links WHERE namespace = $1 AND subject = $2 LIMIT 1',
      [this.namespace, s],
    );
    const uid = toOptionalTrimmedString(rows[0]?.user_id);
    return uid || null;
  }

  async listSubjectsByUserId(userId: string): Promise<string[]> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) return [];
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      'SELECT subject FROM identity_links WHERE namespace = $1 AND user_id = $2 ORDER BY created_at_ms ASC',
      [this.namespace, uid],
    );
    return rows.map((r) => toOptionalTrimmedString(r?.subject)).filter(Boolean) as string[];
  }

  async linkSubjectToUserId(input: {
    userId: string;
    subject: string;
    allowMoveIfSoleIdentity?: boolean;
  }): Promise<LinkIdentityResult> {
    const userId = toOptionalTrimmedString(input.userId);
    const subject = toOptionalTrimmedString(input.subject);
    if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
    if (!subject) return { ok: false, code: 'invalid_args', message: 'Missing subject' };
    const allowMove = Boolean(input.allowMoveIfSoleIdentity);
    const pool = await this.poolPromise;
    const now = Date.now();

    try {
      const existing = await pool.query(
        'SELECT user_id, created_at_ms FROM identity_links WHERE namespace = $1 AND subject = $2 LIMIT 1',
        [this.namespace, subject],
      );
      const existingUserId = toOptionalTrimmedString(existing.rows[0]?.user_id);
      const createdAtMsExisting = typeof existing.rows[0]?.created_at_ms === 'number'
        ? existing.rows[0].created_at_ms
        : Number(existing.rows[0]?.created_at_ms);

      if (existingUserId && existingUserId !== userId) {
        if (!allowMove) {
          return { ok: false, code: 'already_linked', message: 'Subject is already linked to a different user' };
        }

        const count = await pool.query(
          'SELECT COUNT(*)::bigint AS c FROM identity_links WHERE namespace = $1 AND user_id = $2',
          [this.namespace, existingUserId],
        );
        const cRaw = count.rows[0]?.c;
        const c = typeof cRaw === 'number' ? cRaw : Number(cRaw);
        if (!Number.isFinite(c) || c !== 1) {
          return {
            ok: false,
            code: 'already_linked',
            message: 'Subject is linked to a different user with other identities; merge is not allowed',
          };
        }

        await pool.query(
          `
            UPDATE identity_links
            SET user_id = $3, record_json = $4, updated_at_ms = $5
            WHERE namespace = $1 AND subject = $2
          `,
          [
            this.namespace,
            subject,
            userId,
            {
              version: 'identity_subject_v1',
              subject,
              userId,
              createdAtMs: Number.isFinite(createdAtMsExisting) && createdAtMsExisting > 0 ? Math.floor(createdAtMsExisting) : now,
              updatedAtMs: now,
            } satisfies IdentitySubjectRecord,
            now,
          ],
        );

        return { ok: true, movedFromUserId: existingUserId };
      }

      await pool.query(
        `
          INSERT INTO identity_links (namespace, subject, user_id, record_json, created_at_ms, updated_at_ms)
          VALUES ($1, $2, $3, $4, $5, $6)
          ON CONFLICT (namespace, subject)
          DO UPDATE SET user_id = EXCLUDED.user_id, record_json = EXCLUDED.record_json, updated_at_ms = EXCLUDED.updated_at_ms
        `,
        [
          this.namespace,
          subject,
          userId,
          {
            version: 'identity_subject_v1',
            subject,
            userId,
            createdAtMs: Number.isFinite(createdAtMsExisting) && createdAtMsExisting > 0 ? Math.floor(createdAtMsExisting) : now,
            updatedAtMs: now,
          } satisfies IdentitySubjectRecord,
          Number.isFinite(createdAtMsExisting) && createdAtMsExisting > 0 ? Math.floor(createdAtMsExisting) : now,
          now,
        ],
      );
      return { ok: true };
    } catch (e: unknown) {
      return { ok: false, code: 'internal', message: e instanceof Error ? e.message : 'Failed to link identity' };
    }
  }

  async unlinkSubjectFromUserId(input: { userId: string; subject: string }): Promise<UnlinkIdentityResult> {
    const userId = toOptionalTrimmedString(input.userId);
    const subject = toOptionalTrimmedString(input.subject);
    if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
    if (!subject) return { ok: false, code: 'invalid_args', message: 'Missing subject' };

    const pool = await this.poolPromise;
    try {
      const existing = await pool.query(
        'SELECT user_id FROM identity_links WHERE namespace = $1 AND subject = $2 LIMIT 1',
        [this.namespace, subject],
      );
      const existingUserId = toOptionalTrimmedString(existing.rows[0]?.user_id);
      if (!existingUserId || existingUserId !== userId) {
        return { ok: false, code: 'not_found', message: 'Subject is not linked to this user' };
      }

      const count = await pool.query(
        'SELECT COUNT(*)::bigint AS c FROM identity_links WHERE namespace = $1 AND user_id = $2',
        [this.namespace, userId],
      );
      const cRaw = count.rows[0]?.c;
      const c = typeof cRaw === 'number' ? cRaw : Number(cRaw);
      if (!Number.isFinite(c) || c <= 1) {
        return { ok: false, code: 'cannot_unlink_last_identity', message: 'Refusing to remove the last remaining identity' };
      }

      await pool.query(
        'DELETE FROM identity_links WHERE namespace = $1 AND subject = $2 AND user_id = $3',
        [this.namespace, subject, userId],
      );
      return { ok: true };
    } catch (e: unknown) {
      return { ok: false, code: 'internal', message: e instanceof Error ? e.message : 'Failed to unlink identity' };
    }
  }

  async getAppSessionVersionByUserId(userId: string): Promise<string | null> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) return null;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      'SELECT session_version FROM app_session_versions WHERE namespace = $1 AND user_id = $2 LIMIT 1',
      [this.namespace, uid],
    );
    const v = toOptionalTrimmedString(rows[0]?.session_version);
    return v || null;
  }

  async ensureAppSessionVersionByUserId(userId: string): Promise<string> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) throw new Error('Missing userId');
    const pool = await this.poolPromise;
    const now = Date.now();

    const next = generateAppSessionVersion();
    await pool.query(
      `
        INSERT INTO app_session_versions (namespace, user_id, session_version, record_json, created_at_ms, updated_at_ms)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (namespace, user_id) DO NOTHING
      `,
      [
        this.namespace,
        uid,
        next,
        {
          version: 'app_session_version_v1',
          userId: uid,
          appSessionVersion: next,
          createdAtMs: now,
          updatedAtMs: now,
        } satisfies AppSessionVersionRecord,
        now,
        now,
      ],
    );

    const { rows } = await pool.query(
      'SELECT session_version FROM app_session_versions WHERE namespace = $1 AND user_id = $2 LIMIT 1',
      [this.namespace, uid],
    );
    const v = toOptionalTrimmedString(rows[0]?.session_version);
    return v || next;
  }

  async rotateAppSessionVersionByUserId(userId: string): Promise<string> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) throw new Error('Missing userId');
    const pool = await this.poolPromise;
    const now = Date.now();

    const next = generateAppSessionVersion();
    await pool.query(
      `
        INSERT INTO app_session_versions (namespace, user_id, session_version, record_json, created_at_ms, updated_at_ms)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (namespace, user_id)
        DO UPDATE SET session_version = EXCLUDED.session_version, record_json = EXCLUDED.record_json, updated_at_ms = EXCLUDED.updated_at_ms
      `,
      [
        this.namespace,
        uid,
        next,
        {
          version: 'app_session_version_v1',
          userId: uid,
          appSessionVersion: next,
          createdAtMs: now,
          updatedAtMs: now,
        } satisfies AppSessionVersionRecord,
        now,
        now,
      ],
    );
    return next;
  }
}

export function createIdentityStore(input: {
  config?: ThresholdEd25519KeyStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): IdentityStore {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const prefix = toIdentityPrefix(config);

  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'cloudflare-do') {
    const namespace = resolveDoNamespaceFromConfig(config);
    if (!namespace) {
      throw new Error('cloudflare-do identity store selected but no Durable Object namespace was provided (expected config.namespace)');
    }
    const objectName = toOptionalTrimmedString((config as { objectName?: unknown }).objectName)
      || toOptionalTrimmedString((config as { name?: unknown }).name)
      || THRESHOLD_ED25519_DO_OBJECT_NAME_DEFAULT;
    input.logger.info('[identity] Using Cloudflare Durable Object identity store');
    return new CloudflareDurableObjectIdentityStore({ namespace, objectName, prefix });
  }

  if (kind === 'in-memory') {
    input.logger.info('[identity] Using in-memory identity store (non-persistent)');
    return new InMemoryIdentityStore(prefix);
  }

  if (kind === 'upstash-redis-rest') {
    const url = toOptionalTrimmedString(config.url) || toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
    const token = toOptionalTrimmedString(config.token) || toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
    if (!url || !token) {
      throw new Error('Upstash identity store enabled but url/token are not both set');
    }
    input.logger.info('[identity] Using Upstash REST identity store');
    return new UpstashRedisRestIdentityStore({ url, token, prefix });
  }

  if (kind === 'redis-tcp') {
    if (!input.isNode) {
      input.logger.warn('[identity] redis-tcp identity store is not supported in this runtime; falling back to in-memory');
      return new InMemoryIdentityStore(prefix);
    }
    const redisUrl = toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL);
    if (!redisUrl) {
      throw new Error('redis-tcp identity store enabled but redisUrl is not set');
    }
    input.logger.info('[identity] Using redis-tcp identity store');
    return new RedisTcpIdentityStore({ redisUrl, prefix });
  }

  if (kind === 'postgres') {
    if (!input.isNode) {
      throw new Error('[identity] postgres identity store is not supported in this runtime');
    }
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl) throw new Error('[identity] postgres identity store enabled but POSTGRES_URL is not set');
    input.logger.info('[identity] Using Postgres identity store');
    return new PostgresIdentityStore({ postgresUrl, namespace: prefix });
  }

  // Env-shaped config
  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error('Upstash identity store enabled but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set');
    }
    input.logger.info('[identity] Using Upstash REST identity store');
    return new UpstashRedisRestIdentityStore({ url: upstashUrl, token: upstashToken, prefix });
  }

  const redisUrl = toOptionalTrimmedString(config.REDIS_URL);
  if (redisUrl) {
    if (!input.isNode) {
      input.logger.warn('[identity] REDIS_URL is set but TCP Redis is not supported in this runtime; falling back to in-memory');
      return new InMemoryIdentityStore(prefix);
    }
    input.logger.info('[identity] Using redis-tcp identity store');
    return new RedisTcpIdentityStore({ redisUrl, prefix });
  }

  const postgresUrl = getPostgresUrlFromConfig(config);
  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error('[identity] POSTGRES_URL is set but Postgres is not supported in this runtime');
    }
    input.logger.info('[identity] Using Postgres identity store');
    return new PostgresIdentityStore({ postgresUrl, namespace: prefix });
  }

  input.logger.info('[identity] Using in-memory identity store (non-persistent)');
  return new InMemoryIdentityStore(prefix);
}
