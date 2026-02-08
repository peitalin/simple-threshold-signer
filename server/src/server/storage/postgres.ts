import type { NormalizedLogger } from '../core/logger';
import { toOptionalTrimmedString } from '@shared/utils/validation';

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
    // Legacy / unused bookkeeping table (safe to drop).
    await pool.query('DROP TABLE IF EXISTS tatchi_sdk_migrations');

    // One-time: drop the historical `tatchi_` prefix from table names.
    // Keep index names stable (they may still contain `tatchi_`) to avoid accidental duplicate indexes.
    await pool.query(`
      DO $$
      BEGIN
        IF to_regclass('tatchi_webauthn_authenticators') IS NOT NULL AND to_regclass('webauthn_authenticators') IS NULL THEN
          ALTER TABLE tatchi_webauthn_authenticators RENAME TO webauthn_authenticators;
        END IF;
        IF to_regclass('tatchi_webauthn_credential_bindings') IS NOT NULL AND to_regclass('webauthn_credential_bindings') IS NULL THEN
          ALTER TABLE tatchi_webauthn_credential_bindings RENAME TO webauthn_credential_bindings;
        END IF;
        IF to_regclass('tatchi_webauthn_challenges') IS NOT NULL AND to_regclass('webauthn_challenges') IS NULL THEN
          ALTER TABLE tatchi_webauthn_challenges RENAME TO webauthn_challenges;
        END IF;
        IF to_regclass('tatchi_threshold_ed25519_keys') IS NOT NULL AND to_regclass('threshold_ed25519_keys') IS NULL THEN
          ALTER TABLE tatchi_threshold_ed25519_keys RENAME TO threshold_ed25519_keys;
        END IF;
        IF to_regclass('tatchi_threshold_ed25519_sessions') IS NOT NULL AND to_regclass('threshold_ed25519_sessions') IS NULL THEN
          ALTER TABLE tatchi_threshold_ed25519_sessions RENAME TO threshold_ed25519_sessions;
        END IF;
        IF to_regclass('tatchi_threshold_ecdsa_signing_sessions') IS NOT NULL AND to_regclass('threshold_ecdsa_signing_sessions') IS NULL THEN
          ALTER TABLE tatchi_threshold_ecdsa_signing_sessions RENAME TO threshold_ecdsa_signing_sessions;
        END IF;
        IF to_regclass('tatchi_threshold_ecdsa_presignatures') IS NOT NULL AND to_regclass('threshold_ecdsa_presignatures') IS NULL THEN
          ALTER TABLE tatchi_threshold_ecdsa_presignatures RENAME TO threshold_ecdsa_presignatures;
        END IF;
        IF to_regclass('tatchi_device_linking_sessions') IS NOT NULL AND to_regclass('device_linking_sessions') IS NULL THEN
          ALTER TABLE tatchi_device_linking_sessions RENAME TO device_linking_sessions;
        END IF;
        IF to_regclass('tatchi_near_public_keys') IS NOT NULL AND to_regclass('near_public_keys') IS NULL THEN
          ALTER TABLE tatchi_near_public_keys RENAME TO near_public_keys;
        END IF;
        IF to_regclass('tatchi_identity_links') IS NOT NULL AND to_regclass('identity_links') IS NULL THEN
          ALTER TABLE tatchi_identity_links RENAME TO identity_links;
        END IF;
        IF to_regclass('tatchi_app_session_versions') IS NOT NULL AND to_regclass('app_session_versions') IS NULL THEN
          ALTER TABLE tatchi_app_session_versions RENAME TO app_session_versions;
        END IF;
      END $$;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS webauthn_authenticators (
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
      CREATE TABLE IF NOT EXISTS webauthn_credential_bindings (
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
      CREATE TABLE IF NOT EXISTS webauthn_challenges (
        namespace TEXT NOT NULL,
        challenge_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, challenge_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS tatchi_webauthn_challenges_expires_idx
      ON webauthn_challenges (expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS threshold_ed25519_keys (
        namespace TEXT NOT NULL,
        relayer_key_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        PRIMARY KEY (namespace, relayer_key_id)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS threshold_ed25519_sessions (
        namespace TEXT NOT NULL,
        kind TEXT NOT NULL,
        session_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        remaining_uses INTEGER,
        PRIMARY KEY (namespace, kind, session_id),
        CHECK (kind IN ('mpc', 'signing', 'coordinator', 'auth'))
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS tatchi_threshold_ed25519_sessions_expires_idx
      ON threshold_ed25519_sessions (expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS threshold_ecdsa_signing_sessions (
        namespace TEXT NOT NULL,
        signing_session_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, signing_session_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS tatchi_threshold_ecdsa_signing_sessions_expires_idx
      ON threshold_ecdsa_signing_sessions (expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS threshold_ecdsa_presignatures (
        namespace TEXT NOT NULL,
        relayer_key_id TEXT NOT NULL,
        presignature_id TEXT NOT NULL,
        state TEXT NOT NULL,
        record_json JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        reserved_at_ms BIGINT,
        reserve_expires_at_ms BIGINT,
        PRIMARY KEY (namespace, relayer_key_id, presignature_id),
        CHECK (state IN ('available', 'reserved'))
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS tatchi_threshold_ecdsa_presignatures_state_idx
      ON threshold_ecdsa_presignatures (namespace, relayer_key_id, state, created_at_ms)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS tatchi_threshold_ecdsa_presignatures_reserved_expires_idx
      ON threshold_ecdsa_presignatures (reserve_expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS device_linking_sessions (
        namespace TEXT NOT NULL,
        session_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, session_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS tatchi_device_linking_sessions_expires_idx
      ON device_linking_sessions (expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS near_public_keys (
        namespace TEXT NOT NULL,
        user_id TEXT NOT NULL,
        public_key TEXT NOT NULL,
        record_json JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, user_id, public_key)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS tatchi_near_public_keys_user_idx
      ON near_public_keys (namespace, user_id)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS identity_links (
        namespace TEXT NOT NULL,
        subject TEXT NOT NULL,
        user_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, subject)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS tatchi_identity_links_user_idx
      ON identity_links (namespace, user_id)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS app_session_versions (
        namespace TEXT NOT NULL,
        user_id TEXT NOT NULL,
        session_version TEXT NOT NULL,
        record_json JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, user_id)
      )
    `);

    // ==========================
    // One-time table consolidations
    // ==========================

    // Consolidate webauthn challenges tables.
    await pool.query(`
      DO $$
      BEGIN
        IF to_regclass('tatchi_webauthn_login_challenges') IS NOT NULL THEN
          INSERT INTO webauthn_challenges (namespace, challenge_id, record_json, expires_at_ms)
          SELECT namespace, challenge_id, record_json, expires_at_ms
          FROM tatchi_webauthn_login_challenges
          ON CONFLICT (namespace, challenge_id) DO NOTHING;
          DROP TABLE tatchi_webauthn_login_challenges;
        END IF;
      END $$;
    `);
    await pool.query(`
      DO $$
      BEGIN
        IF to_regclass('tatchi_webauthn_sync_challenges') IS NOT NULL THEN
          INSERT INTO webauthn_challenges (namespace, challenge_id, record_json, expires_at_ms)
          SELECT namespace, challenge_id, record_json, expires_at_ms
          FROM tatchi_webauthn_sync_challenges
          ON CONFLICT (namespace, challenge_id) DO NOTHING;
          DROP TABLE tatchi_webauthn_sync_challenges;
        END IF;
      END $$;
    `);

    // Consolidate threshold ed25519 session tables.
    await pool.query(`
      DO $$
      BEGIN
        IF to_regclass('tatchi_threshold_ed25519_mpc_sessions') IS NOT NULL THEN
          INSERT INTO threshold_ed25519_sessions (namespace, kind, session_id, record_json, expires_at_ms)
          SELECT namespace, 'mpc', session_id, record_json, expires_at_ms
          FROM tatchi_threshold_ed25519_mpc_sessions
          ON CONFLICT (namespace, kind, session_id) DO NOTHING;
          DROP TABLE tatchi_threshold_ed25519_mpc_sessions;
        END IF;
      END $$;
    `);
    await pool.query(`
      DO $$
      BEGIN
        IF to_regclass('tatchi_threshold_ed25519_signing_sessions') IS NOT NULL THEN
          INSERT INTO threshold_ed25519_sessions (namespace, kind, session_id, record_json, expires_at_ms)
          SELECT namespace, 'signing', session_id, record_json, expires_at_ms
          FROM tatchi_threshold_ed25519_signing_sessions
          ON CONFLICT (namespace, kind, session_id) DO NOTHING;
          DROP TABLE tatchi_threshold_ed25519_signing_sessions;
        END IF;
      END $$;
    `);
    await pool.query(`
      DO $$
      BEGIN
        IF to_regclass('tatchi_threshold_ed25519_coordinator_sessions') IS NOT NULL THEN
          INSERT INTO threshold_ed25519_sessions (namespace, kind, session_id, record_json, expires_at_ms)
          SELECT namespace, 'coordinator', session_id, record_json, expires_at_ms
          FROM tatchi_threshold_ed25519_coordinator_sessions
          ON CONFLICT (namespace, kind, session_id) DO NOTHING;
          DROP TABLE tatchi_threshold_ed25519_coordinator_sessions;
        END IF;
      END $$;
    `);
    await pool.query(`
      DO $$
      BEGIN
        IF to_regclass('tatchi_threshold_ed25519_auth_sessions') IS NOT NULL THEN
          INSERT INTO threshold_ed25519_sessions (namespace, kind, session_id, record_json, expires_at_ms, remaining_uses)
          SELECT namespace, 'auth', session_id, record_json, expires_at_ms, remaining_uses
          FROM tatchi_threshold_ed25519_auth_sessions
          ON CONFLICT (namespace, kind, session_id) DO NOTHING;
          DROP TABLE tatchi_threshold_ed25519_auth_sessions;
        END IF;
      END $$;
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
