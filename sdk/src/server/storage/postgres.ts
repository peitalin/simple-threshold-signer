import type { NormalizedLogger } from '../core/logger';
import { toOptionalTrimmedString } from '../../utils/validation';

type PgPool = {
  query: (text: string, values?: unknown[]) => Promise<{ rows: any[] }>;
  end?: () => Promise<void>;
};

type PgModuleLike = {
  Pool?: new (opts: { connectionString: string }) => PgPool;
  default?: { Pool?: new (opts: { connectionString: string }) => PgPool };
};

const poolsByUrl = new Map<string, Promise<PgPool>>();

async function loadPgPoolCtor(): Promise<new (opts: { connectionString: string }) => PgPool> {
  let mod: PgModuleLike;
  try {
    mod = (await import('pg')) as unknown as PgModuleLike;
  } catch (err) {
    const msg = String((err && typeof err === 'object' && 'message' in err) ? (err as any).message : err || '');
    throw new Error(`Postgres store selected but 'pg' dependency is not available${msg ? `: ${msg}` : ''}`);
  }
  const ctor = mod.Pool || mod.default?.Pool;
  if (!ctor) throw new Error(`Postgres store selected but failed to load Pool constructor from 'pg'`);
  return ctor;
}

export function getPostgresUrlFromConfig(config: Record<string, unknown>): string | null {
  return toOptionalTrimmedString(config.postgresUrl) || toOptionalTrimmedString(config.POSTGRES_URL);
}

export async function getPostgresPool(postgresUrl: string): Promise<PgPool> {
  const url = String(postgresUrl || '').trim();
  if (!url) throw new Error('Missing POSTGRES_URL');
  const existing = poolsByUrl.get(url);
  if (existing) return existing;

  const created = (async () => {
    const Pool = await loadPgPoolCtor();
    return new Pool({ connectionString: url });
  })();
  poolsByUrl.set(url, created);
  return created;
}

const MIGRATION_LOCK_ID = 9452360123581;

export async function ensurePostgresSchema(input: {
  postgresUrl: string;
  logger: NormalizedLogger;
}): Promise<void> {
  const pool = await getPostgresPool(input.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [MIGRATION_LOCK_ID]);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS tatchi_sdk_migrations (
        id TEXT PRIMARY KEY,
        applied_at_ms BIGINT NOT NULL
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS tatchi_webauthn_authenticators (
        namespace TEXT NOT NULL,
        user_id TEXT NOT NULL,
        credential_id_b64u TEXT NOT NULL,
        credential_public_key_b64u TEXT NOT NULL,
        counter BIGINT NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, user_id, credential_id_b64u)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS tatchi_webauthn_credential_bindings (
        namespace TEXT NOT NULL,
        rp_id TEXT NOT NULL,
        credential_id_b64u TEXT NOT NULL,
        record_json JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, rp_id, credential_id_b64u)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS tatchi_webauthn_login_challenges (
        namespace TEXT NOT NULL,
        challenge_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, challenge_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS tatchi_webauthn_login_challenges_expires_idx
      ON tatchi_webauthn_login_challenges (expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS tatchi_webauthn_sync_challenges (
        namespace TEXT NOT NULL,
        challenge_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, challenge_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS tatchi_webauthn_sync_challenges_expires_idx
      ON tatchi_webauthn_sync_challenges (expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS tatchi_threshold_ed25519_keys (
        namespace TEXT NOT NULL,
        relayer_key_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        PRIMARY KEY (namespace, relayer_key_id)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS tatchi_threshold_ed25519_mpc_sessions (
        namespace TEXT NOT NULL,
        session_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, session_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS tatchi_threshold_ed25519_mpc_sessions_expires_idx
      ON tatchi_threshold_ed25519_mpc_sessions (expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS tatchi_threshold_ed25519_signing_sessions (
        namespace TEXT NOT NULL,
        session_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, session_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS tatchi_threshold_ed25519_signing_sessions_expires_idx
      ON tatchi_threshold_ed25519_signing_sessions (expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS tatchi_threshold_ed25519_coordinator_sessions (
        namespace TEXT NOT NULL,
        session_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, session_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS tatchi_threshold_ed25519_coordinator_sessions_expires_idx
      ON tatchi_threshold_ed25519_coordinator_sessions (expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS tatchi_threshold_ed25519_auth_sessions (
        namespace TEXT NOT NULL,
        session_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        remaining_uses INTEGER NOT NULL,
        PRIMARY KEY (namespace, session_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS tatchi_threshold_ed25519_auth_sessions_expires_idx
      ON tatchi_threshold_ed25519_auth_sessions (expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS tatchi_device_linking_sessions (
        namespace TEXT NOT NULL,
        session_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, session_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS tatchi_device_linking_sessions_expires_idx
      ON tatchi_device_linking_sessions (expires_at_ms)
    `);
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [MIGRATION_LOCK_ID]);
    } catch {
      // ignore unlock failures
    }
  }

  input.logger.info('[postgres] Schema ready');
}
