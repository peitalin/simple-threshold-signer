import type { NormalizedLogger } from './logger';
import type { ThresholdEd25519KeyStoreConfigInput } from './types';
import { THRESHOLD_PREFIX_DEFAULT } from './defaultConfigsServer';
import { isObject as isObjectLoose, toOptionalTrimmedString } from '../../utils/validation';
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
        FROM tatchi_device_linking_sessions
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
        INSERT INTO tatchi_device_linking_sessions (namespace, session_id, record_json, expires_at_ms)
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
      'DELETE FROM tatchi_device_linking_sessions WHERE namespace = $1 AND session_id = $2',
      [this.namespace, id],
    );
  }
}

export function createDeviceLinkingSessionStore(input: {
  config?: ThresholdEd25519KeyStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): DeviceLinkingSessionStore {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const namespace = toDeviceLinkingSessionPrefix(config);

  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'postgres') {
    if (!input.isNode) throw new Error('[link-device] postgres session store is not supported in this runtime');
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl) throw new Error('[link-device] postgres session store enabled but POSTGRES_URL is not set');
    input.logger.info('[link-device] Using Postgres session store');
    return new PostgresDeviceLinkingSessionStore({ postgresUrl, namespace });
  }

  const postgresUrl = getPostgresUrlFromConfig(config);
  if (postgresUrl) {
    if (!input.isNode) throw new Error('[link-device] POSTGRES_URL is set but Postgres is not supported in this runtime');
    input.logger.info('[link-device] Using Postgres session store');
    return new PostgresDeviceLinkingSessionStore({ postgresUrl, namespace });
  }

  input.logger.info('[link-device] Using in-memory session store (non-persistent)');
  return new InMemoryDeviceLinkingSessionStore({ namespace });
}
