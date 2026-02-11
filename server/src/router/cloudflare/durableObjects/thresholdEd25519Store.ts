// Durable Object implementation for threshold signing state.
//
// This is exported from the SDK so Cloudflare Worker hosts can bind it directly
// (by re-exporting from their Worker entrypoint) without vendoring the code.

type DurableObjectStorageLike = {
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown, opts?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<boolean>;
  transaction?<T>(fn: (txn: DurableObjectStorageLike) => Promise<T>): Promise<T>;
};

type DurableObjectStateLike = {
  storage: DurableObjectStorageLike;
};

type DoOk<T> = { ok: true; value: T };
type DoErr = { ok: false; code: string; message: string };
type DoResp<T> = DoOk<T> | DoErr;

type DoReq =
  | { op: 'get'; key: string }
  | { op: 'set'; key: string; value: unknown; ttlMs?: number }
  | { op: 'del'; key: string }
  | { op: 'getdel'; key: string }
  | { op: 'authConsumeUseCount'; key: string }
  | { op: 'ecdsaPresignPut'; listKey: string; value: unknown }
  | { op: 'ecdsaPresignReserve'; listKey: string; reservedKeyPrefix: string; ttlMs?: number }
  | { op: 'ecdsaPresignSessionCreate'; key: string; value: unknown; ttlMs?: number }
  | { op: 'ecdsaPresignSessionAdvanceCas'; key: string; expectedVersion: number; value: unknown; ttlMs?: number };

type AuthEntry = {
  record: { expiresAtMs: number; relayerKeyId: string; userId: string; rpId: string; participantIds: number[] };
  remainingUses: number;
  expiresAtMs: number;
};

type PresignSessionRecord = {
  expiresAtMs: number;
  version: number;
};

function json(body: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    status: init?.status ?? 200,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      ...(init?.headers || {}),
    },
  });
}

function ok<T>(value: T): DoOk<T> {
  return { ok: true, value };
}

function err(code: string, message: string): DoErr {
  return { ok: false, code, message };
}

function toKey(input: unknown): string {
  const k = typeof input === 'string' ? input.trim() : '';
  return k;
}

function toTtlSeconds(ttlMs: unknown): number | null {
  if (ttlMs === undefined || ttlMs === null) return null;
  const n = Number(ttlMs);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.max(1, Math.ceil(n / 1000));
}

function isObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function parseAuthEntry(raw: unknown): AuthEntry | null {
  if (!isObject(raw)) return null;
  const record = (raw as { record?: unknown }).record;
  const remainingUses = (raw as { remainingUses?: unknown }).remainingUses;
  const expiresAtMs = (raw as { expiresAtMs?: unknown }).expiresAtMs;
  if (!isObject(record)) return null;
  if (typeof remainingUses !== 'number' || !Number.isFinite(remainingUses)) return null;
  if (typeof expiresAtMs !== 'number' || !Number.isFinite(expiresAtMs)) return null;
  // Minimal record shape check (full validation happens on the service layer).
  const rec = record as Record<string, unknown>;
  if (typeof rec.userId !== 'string' || typeof rec.rpId !== 'string' || typeof rec.relayerKeyId !== 'string') return null;
  if (typeof rec.expiresAtMs !== 'number' || !Number.isFinite(rec.expiresAtMs)) return null;
  if (!Array.isArray(rec.participantIds)) return null;
  return raw as AuthEntry;
}

function parsePresignSessionRecord(raw: unknown): PresignSessionRecord | null {
  if (!isObject(raw)) return null;
  const expiresAtMs = (raw as { expiresAtMs?: unknown }).expiresAtMs;
  const version = (raw as { version?: unknown }).version;
  if (typeof expiresAtMs !== 'number' || !Number.isFinite(expiresAtMs)) return null;
  if (typeof version !== 'number' || !Number.isFinite(version)) return null;
  return { expiresAtMs, version };
}

async function withTxn<T>(state: DurableObjectStateLike, fn: (store: DurableObjectStorageLike) => Promise<T>): Promise<T> {
  if (typeof state.storage.transaction === 'function') {
    return await state.storage.transaction(fn);
  }
  // Fallback: best-effort single-threaded behavior; DO runtime should support transactions,
  // but don't hard-require it in the SDK.
  return await fn(state.storage);
}

export class ThresholdEd25519StoreDurableObject {
  private readonly state: DurableObjectStateLike;

  constructor(state: DurableObjectStateLike, _env: unknown) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    if (request.method.toUpperCase() !== 'POST') {
      return json(err('method_not_allowed', 'POST required'), { status: 405 });
    }

    let body: unknown;
    try {
      body = await request.json();
    } catch {
      body = null;
    }
    if (!isObject(body)) return json(err('invalid_body', 'Expected JSON object'));
    const op = (body as { op?: unknown }).op;
    if (typeof op !== 'string') return json(err('invalid_body', 'Missing op'));

    const req = body as DoReq;
    if (op === 'get') {
      const key = toKey((req as { key?: unknown }).key);
      if (!key) return json(err('invalid_body', 'Missing key'));
      const value = await this.state.storage.get(key);
      return json(ok(value ?? null));
    }
    if (op === 'set') {
      const key = toKey((req as { key?: unknown }).key);
      if (!key) return json(err('invalid_body', 'Missing key'));
      const ttl = toTtlSeconds((req as { ttlMs?: unknown }).ttlMs);
      await this.state.storage.put(key, (req as { value?: unknown }).value, ttl ? { expirationTtl: ttl } : undefined);
      return json(ok(true));
    }
    if (op === 'del') {
      const key = toKey((req as { key?: unknown }).key);
      if (!key) return json(err('invalid_body', 'Missing key'));
      await this.state.storage.delete(key);
      return json(ok(true));
    }
    if (op === 'getdel') {
      const key = toKey((req as { key?: unknown }).key);
      if (!key) return json(err('invalid_body', 'Missing key'));
      const value = await withTxn(this.state, async (store) => {
        const v = await store.get(key);
        await store.delete(key);
        return v ?? null;
      });
      return json(ok(value));
    }
    if (op === 'authConsumeUseCount') {
      const key = toKey((req as { key?: unknown }).key);
      if (!key) return json(err('invalid_body', 'Missing key'));

      const res: DoResp<unknown> = await withTxn(this.state, async (store) => {
        const raw = await store.get(key);
        const entry = parseAuthEntry(raw);
        if (!entry) return err('unauthorized', 'threshold session expired or invalid');

        if (Date.now() > entry.expiresAtMs) {
          await store.delete(key);
          return err('unauthorized', 'threshold session expired');
        }
        if (entry.remainingUses <= 0) return err('unauthorized', 'threshold session exhausted');

        entry.remainingUses -= 1;
        const ttlSeconds = Math.max(1, Math.ceil(Math.max(0, entry.expiresAtMs - Date.now()) / 1000));
        await store.put(key, entry, { expirationTtl: ttlSeconds });

        return ok({ remainingUses: entry.remainingUses });
      });

      return json(res);
    }

    if (op === 'ecdsaPresignPut') {
      const listKey = toKey((req as { listKey?: unknown }).listKey);
      if (!listKey) return json(err('invalid_body', 'Missing listKey'));
      const value = (req as { value?: unknown }).value;
      await withTxn(this.state, async (store) => {
        const raw = await store.get(listKey);
        const list = Array.isArray(raw) ? [...raw] : [];
        list.push(value);
        await store.put(listKey, list);
      });
      return json(ok(true));
    }

    if (op === 'ecdsaPresignReserve') {
      const listKey = toKey((req as { listKey?: unknown }).listKey);
      const reservedKeyPrefix = toKey((req as { reservedKeyPrefix?: unknown }).reservedKeyPrefix);
      const ttlSeconds = toTtlSeconds((req as { ttlMs?: unknown }).ttlMs) || 120;
      if (!listKey) return json(err('invalid_body', 'Missing listKey'));
      if (!reservedKeyPrefix) return json(err('invalid_body', 'Missing reservedKeyPrefix'));

      const value = await withTxn(this.state, async (store) => {
        const raw = await store.get(listKey);
        const list = Array.isArray(raw) ? [...raw] : [];
        if (!list.length) return null;
        const item = list.shift();
        await store.put(listKey, list);

        const presignatureId = isObject(item) ? toKey((item as { presignatureId?: unknown }).presignatureId) : '';
        if (presignatureId) {
          await store.put(`${reservedKeyPrefix}${presignatureId}`, item, { expirationTtl: ttlSeconds });
        }
        return item ?? null;
      });

      return json(ok(value));
    }

    if (op === 'ecdsaPresignSessionCreate') {
      const key = toKey((req as { key?: unknown }).key);
      const value = (req as { value?: unknown }).value;
      const ttlSeconds = toTtlSeconds((req as { ttlMs?: unknown }).ttlMs);
      if (!key) return json(err('invalid_body', 'Missing key'));
      if (!parsePresignSessionRecord(value)) return json(err('invalid_body', 'Invalid presign session record'));

      const result = await withTxn(this.state, async (store) => {
        const nowMs = Date.now();
        const existingRaw = await store.get(key);
        if (existingRaw !== null && existingRaw !== undefined) {
          const existing = parsePresignSessionRecord(existingRaw);
          if (!existing || existing.expiresAtMs > nowMs) {
            return { status: 'exists' };
          }
        }
        await store.put(key, value, ttlSeconds ? { expirationTtl: ttlSeconds } : undefined);
        return { status: 'ok' };
      });

      return json(ok(result));
    }

    if (op === 'ecdsaPresignSessionAdvanceCas') {
      const key = toKey((req as { key?: unknown }).key);
      const expectedVersionRaw = (req as { expectedVersion?: unknown }).expectedVersion;
      const value = (req as { value?: unknown }).value;
      const ttlSeconds = toTtlSeconds((req as { ttlMs?: unknown }).ttlMs);
      if (!key) return json(err('invalid_body', 'Missing key'));
      const expectedVersion = Math.floor(Number(expectedVersionRaw));
      if (!Number.isFinite(expectedVersion) || expectedVersion < 1) {
        return json(err('invalid_body', 'Invalid expectedVersion'));
      }
      const nextRecord = parsePresignSessionRecord(value);
      if (!nextRecord) return json(err('invalid_body', 'Invalid presign session record'));

      const result = await withTxn(this.state, async (store) => {
        const nowMs = Date.now();
        const existingRaw = await store.get(key);
        if (existingRaw === null || existingRaw === undefined) return { status: 'not_found' };
        const existing = parsePresignSessionRecord(existingRaw);
        if (!existing) return { status: 'not_found' };
        if (existing.expiresAtMs <= nowMs) {
          await store.delete(key);
          return { status: 'expired' };
        }
        if (existing.version !== expectedVersion) return { status: 'version_mismatch' };
        await store.put(key, value, ttlSeconds ? { expirationTtl: ttlSeconds } : undefined);
        return { status: 'ok', record: value };
      });

      return json(ok(result));
    }

    return json(err('invalid_body', `Unknown op: ${op}`));
  }
}
