import { test, expect } from '@playwright/test';
import { ensurePostgresSchema, getPostgresPool } from '../../server/src/storage/postgres';
import { createThresholdEcdsaSigningStores } from '../../server/src/core/ThresholdService/stores/EcdsaSigningStore';

function randPrefix(tag: string): string {
  return `test:${tag}:${Date.now()}:${Math.random().toString(16).slice(2)}:`;
}

function makeSigningSessionRecord(args: { relayerKeyId: string; presignatureId: string }) {
  return {
    expiresAtMs: Date.now() + 60_000,
    mpcSessionId: 'mpc-session-1',
    relayerKeyId: args.relayerKeyId,
    signingDigestB64u: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    userId: 'user-1',
    rpId: 'example.localhost',
    clientVerifyingShareB64u: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    participantIds: [1, 2],
    presignatureId: args.presignatureId,
    entropyB64u: 'ccccccccccccccccccccccccccccccccccccccccccc',
  };
}

function makePresignRecord(args: { relayerKeyId: string; presignatureId: string; createdAtMs?: number }) {
  return {
    relayerKeyId: args.relayerKeyId,
    presignatureId: args.presignatureId,
    bigRB64u: 'ddddddddddddddddddddddddddddddddddddddddddd',
    kShareB64u: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    sigmaShareB64u: 'fffffffffffffffffffffffffffffffffffffffffff',
    createdAtMs: args.createdAtMs ?? Date.now(),
  };
}

function makePresignSessionRecord(args?: { version?: number; stage?: 'triples' | 'triples_done' | 'presign' | 'done' }) {
  const version = args?.version ?? 1;
  return {
    expiresAtMs: Date.now() + 60_000,
    userId: 'user-1',
    rpId: 'example.localhost',
    relayerKeyId: 'rk-presign',
    participantIds: [1, 2],
    clientParticipantId: 1,
    relayerParticipantId: 2,
    stage: args?.stage ?? 'triples',
    version,
    wasmSessionStateB64u: 'cHJlc2lnbi1zZXNzaW9uLXN0YXRl',
    createdAtMs: Date.now(),
    updatedAtMs: Date.now(),
  };
}

test.describe('threshold-ecdsa durable presign pool + signing sessions', () => {
  test.describe('Postgres', () => {
    const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
    const enabled = Boolean(postgresUrl);
    const signingPrefix = randPrefix('threshold-ecdsa:signing:pg');
    const presignPrefix = randPrefix('threshold-ecdsa:presign:pg');

    test.beforeAll(async () => {
      test.skip(!enabled, 'POSTGRES_URL not set');
      await ensurePostgresSchema({ postgresUrl, logger: console as any });
    });

    test.afterAll(async () => {
      if (!enabled) return;
      const pool = await getPostgresPool(postgresUrl);
      await pool.query('DELETE FROM threshold_ecdsa_signing_sessions WHERE namespace = $1', [signingPrefix]);
      await pool.query('DELETE FROM threshold_ecdsa_presignatures WHERE namespace = $1', [presignPrefix]);
      await pool.query('DELETE FROM threshold_ecdsa_presign_sessions WHERE namespace = $1', [presignPrefix]);
    });

    test('signingSessionStore take is atomic', async () => {
      test.skip(!enabled, 'POSTGRES_URL not set');
      const { signingSessionStore } = createThresholdEcdsaSigningStores({
        config: {
          kind: 'postgres',
          POSTGRES_URL: postgresUrl,
          THRESHOLD_ECDSA_SIGNING_PREFIX: signingPrefix,
          THRESHOLD_ECDSA_PRESIGN_PREFIX: presignPrefix,
        } as any,
        logger: console as any,
        isNode: true,
      });

      const rec = makeSigningSessionRecord({ relayerKeyId: 'rk-1', presignatureId: 'ps-1' });
      await signingSessionStore.putSigningSession('ss-1', rec as any, 10_000);

      const first = await signingSessionStore.takeSigningSession('ss-1');
      const second = await signingSessionStore.takeSigningSession('ss-1');

      expect(first?.mpcSessionId).toBe(rec.mpcSessionId);
      expect(second).toBeNull();
    });

    test('presignaturePool reserve/consume are single-use under concurrency', async () => {
      test.skip(!enabled, 'POSTGRES_URL not set');
      const { presignaturePool } = createThresholdEcdsaSigningStores({
        config: {
          kind: 'postgres',
          POSTGRES_URL: postgresUrl,
          THRESHOLD_ECDSA_SIGNING_PREFIX: signingPrefix,
          THRESHOLD_ECDSA_PRESIGN_PREFIX: presignPrefix,
        } as any,
        logger: console as any,
        isNode: true,
      });

      const relayerKeyId = 'rk-2';
      await presignaturePool.put(makePresignRecord({ relayerKeyId, presignatureId: 'ps-a', createdAtMs: Date.now() - 2 }) as any);
      await presignaturePool.put(makePresignRecord({ relayerKeyId, presignatureId: 'ps-b', createdAtMs: Date.now() - 1 }) as any);

      const [a, b] = await Promise.all([presignaturePool.reserve(relayerKeyId), presignaturePool.reserve(relayerKeyId)]);
      expect(a && b).toBeTruthy();
      expect(a!.presignatureId).not.toBe(b!.presignatureId);

      const a1 = await presignaturePool.consume(relayerKeyId, a!.presignatureId);
      const a2 = await presignaturePool.consume(relayerKeyId, a!.presignatureId);
      expect(a1?.presignatureId).toBe(a!.presignatureId);
      expect(a2).toBeNull();

      const b1 = await presignaturePool.consume(relayerKeyId, b!.presignatureId);
      const b2 = await presignaturePool.consume(relayerKeyId, b!.presignatureId);
      expect(b1?.presignatureId).toBe(b!.presignatureId);
      expect(b2).toBeNull();
    });

    test('presignaturePool discard prevents consume', async () => {
      test.skip(!enabled, 'POSTGRES_URL not set');
      const { presignaturePool } = createThresholdEcdsaSigningStores({
        config: {
          kind: 'postgres',
          POSTGRES_URL: postgresUrl,
          THRESHOLD_ECDSA_SIGNING_PREFIX: signingPrefix,
          THRESHOLD_ECDSA_PRESIGN_PREFIX: presignPrefix,
        } as any,
        logger: console as any,
        isNode: true,
      });

      const relayerKeyId = 'rk-3';
      await presignaturePool.put(makePresignRecord({ relayerKeyId, presignatureId: 'ps-x' }) as any);
      const reserved = await presignaturePool.reserve(relayerKeyId);
      expect(reserved?.presignatureId).toBe('ps-x');

      await presignaturePool.discard(relayerKeyId, 'ps-x');
      const consumed = await presignaturePool.consume(relayerKeyId, 'ps-x');
      expect(consumed).toBeNull();
    });

    test('presignSessionStore CAS transitions are atomic', async () => {
      test.skip(!enabled, 'POSTGRES_URL not set');
      const { presignSessionStore } = createThresholdEcdsaSigningStores({
        config: {
          kind: 'postgres',
          POSTGRES_URL: postgresUrl,
          THRESHOLD_ECDSA_SIGNING_PREFIX: signingPrefix,
          THRESHOLD_ECDSA_PRESIGN_PREFIX: presignPrefix,
        } as any,
        logger: console as any,
        isNode: true,
      });

      const created = await presignSessionStore.createSession(
        'psess-1',
        makePresignSessionRecord({ version: 1, stage: 'triples' }) as any,
        10_000,
      );
      expect(created.ok).toBe(true);

      const stale = await presignSessionStore.advanceSessionCas({
        id: 'psess-1',
        expectedVersion: 99,
        nextRecord: makePresignSessionRecord({ version: 100, stage: 'triples' }) as any,
        ttlMs: 10_000,
      });
      expect(stale.ok).toBe(false);
      if (!stale.ok) expect(stale.code).toBe('version_mismatch');

      const [a, b] = await Promise.all([
        presignSessionStore.advanceSessionCas({
          id: 'psess-1',
          expectedVersion: 1,
          nextRecord: makePresignSessionRecord({ version: 2, stage: 'triples_done' }) as any,
          ttlMs: 10_000,
        }),
        presignSessionStore.advanceSessionCas({
          id: 'psess-1',
          expectedVersion: 1,
          nextRecord: makePresignSessionRecord({ version: 2, stage: 'triples_done' }) as any,
          ttlMs: 10_000,
        }),
      ]);

      const oks = [a, b].filter((r) => r.ok);
      const errs = [a, b].filter((r) => !r.ok);
      expect(oks.length).toBe(1);
      expect(errs.length).toBe(1);
      if (!errs[0].ok) expect(errs[0].code).toBe('version_mismatch');

      const got = await presignSessionStore.getSession('psess-1');
      expect(got?.version).toBe(2);
      expect(got?.stage).toBe('triples_done');

      await presignSessionStore.deleteSession('psess-1');
      const afterDelete = await presignSessionStore.getSession('psess-1');
      expect(afterDelete).toBeNull();
    });
  });

  test.describe('Redis (tcp)', () => {
    const redisUrl = String(process.env.REDIS_URL || '').trim();
    const enabled = Boolean(redisUrl);
    const signingPrefix = randPrefix('threshold-ecdsa:signing:redis');
    const presignPrefix = randPrefix('threshold-ecdsa:presign:redis');

    test('signingSessionStore take is atomic', async () => {
      test.skip(!enabled, 'REDIS_URL not set');
      const { signingSessionStore } = createThresholdEcdsaSigningStores({
        config: {
          kind: 'redis-tcp',
          REDIS_URL: redisUrl,
          THRESHOLD_ECDSA_SIGNING_PREFIX: signingPrefix,
          THRESHOLD_ECDSA_PRESIGN_PREFIX: presignPrefix,
        } as any,
        logger: console as any,
        isNode: true,
      });

      const rec = makeSigningSessionRecord({ relayerKeyId: 'rk-10', presignatureId: 'ps-10' });
      await signingSessionStore.putSigningSession('ss-10', rec as any, 10_000);

      const first = await signingSessionStore.takeSigningSession('ss-10');
      const second = await signingSessionStore.takeSigningSession('ss-10');

      expect(first?.mpcSessionId).toBe(rec.mpcSessionId);
      expect(second).toBeNull();
    });

    test('presignaturePool reserve/consume are single-use under concurrency', async () => {
      test.skip(!enabled, 'REDIS_URL not set');
      const { presignaturePool } = createThresholdEcdsaSigningStores({
        config: {
          kind: 'redis-tcp',
          REDIS_URL: redisUrl,
          THRESHOLD_ECDSA_SIGNING_PREFIX: signingPrefix,
          THRESHOLD_ECDSA_PRESIGN_PREFIX: presignPrefix,
        } as any,
        logger: console as any,
        isNode: true,
      });

      const relayerKeyId = 'rk-11';
      await presignaturePool.put(makePresignRecord({ relayerKeyId, presignatureId: 'ps-ra', createdAtMs: Date.now() - 2 }) as any);
      await presignaturePool.put(makePresignRecord({ relayerKeyId, presignatureId: 'ps-rb', createdAtMs: Date.now() - 1 }) as any);

      const [a, b] = await Promise.all([presignaturePool.reserve(relayerKeyId), presignaturePool.reserve(relayerKeyId)]);
      expect(a && b).toBeTruthy();
      expect(a!.presignatureId).not.toBe(b!.presignatureId);

      const a1 = await presignaturePool.consume(relayerKeyId, a!.presignatureId);
      const a2 = await presignaturePool.consume(relayerKeyId, a!.presignatureId);
      expect(a1?.presignatureId).toBe(a!.presignatureId);
      expect(a2).toBeNull();

      const b1 = await presignaturePool.consume(relayerKeyId, b!.presignatureId);
      const b2 = await presignaturePool.consume(relayerKeyId, b!.presignatureId);
      expect(b1?.presignatureId).toBe(b!.presignatureId);
      expect(b2).toBeNull();
    });

    test('presignSessionStore CAS transitions are atomic', async () => {
      test.skip(!enabled, 'REDIS_URL not set');
      const { presignSessionStore } = createThresholdEcdsaSigningStores({
        config: {
          kind: 'redis-tcp',
          REDIS_URL: redisUrl,
          THRESHOLD_ECDSA_SIGNING_PREFIX: signingPrefix,
          THRESHOLD_ECDSA_PRESIGN_PREFIX: presignPrefix,
        } as any,
        logger: console as any,
        isNode: true,
      });

      const created = await presignSessionStore.createSession(
        'psess-r1',
        makePresignSessionRecord({ version: 1, stage: 'triples' }) as any,
        10_000,
      );
      expect(created.ok).toBe(true);

      const stale = await presignSessionStore.advanceSessionCas({
        id: 'psess-r1',
        expectedVersion: 99,
        nextRecord: makePresignSessionRecord({ version: 100, stage: 'triples' }) as any,
        ttlMs: 10_000,
      });
      expect(stale.ok).toBe(false);
      if (!stale.ok) expect(stale.code).toBe('version_mismatch');

      const [a, b] = await Promise.all([
        presignSessionStore.advanceSessionCas({
          id: 'psess-r1',
          expectedVersion: 1,
          nextRecord: makePresignSessionRecord({ version: 2, stage: 'triples_done' }) as any,
          ttlMs: 10_000,
        }),
        presignSessionStore.advanceSessionCas({
          id: 'psess-r1',
          expectedVersion: 1,
          nextRecord: makePresignSessionRecord({ version: 2, stage: 'triples_done' }) as any,
          ttlMs: 10_000,
        }),
      ]);

      const oks = [a, b].filter((r) => r.ok);
      const errs = [a, b].filter((r) => !r.ok);
      expect(oks.length).toBe(1);
      expect(errs.length).toBe(1);
      if (!errs[0].ok) expect(errs[0].code).toBe('version_mismatch');

      const got = await presignSessionStore.getSession('psess-r1');
      expect(got?.version).toBe(2);
      expect(got?.stage).toBe('triples_done');

      await presignSessionStore.deleteSession('psess-r1');
      const afterDelete = await presignSessionStore.getSession('psess-r1');
      expect(afterDelete).toBeNull();
    });
  });

  test.describe('Upstash REST', () => {
    const upstashUrl = String(process.env.UPSTASH_REDIS_REST_URL || '').trim();
    const upstashToken = String(process.env.UPSTASH_REDIS_REST_TOKEN || '').trim();
    const enabled = Boolean(upstashUrl && upstashToken);
    const signingPrefix = randPrefix('threshold-ecdsa:signing:upstash');
    const presignPrefix = randPrefix('threshold-ecdsa:presign:upstash');

    test('signingSessionStore take is atomic', async () => {
      test.skip(!enabled, 'UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN not set');
      const { signingSessionStore } = createThresholdEcdsaSigningStores({
        config: {
          kind: 'upstash-redis-rest',
          UPSTASH_REDIS_REST_URL: upstashUrl,
          UPSTASH_REDIS_REST_TOKEN: upstashToken,
          THRESHOLD_ECDSA_SIGNING_PREFIX: signingPrefix,
          THRESHOLD_ECDSA_PRESIGN_PREFIX: presignPrefix,
        } as any,
        logger: console as any,
        isNode: true,
      });

      const rec = makeSigningSessionRecord({ relayerKeyId: 'rk-u1', presignatureId: 'ps-u1' });
      await signingSessionStore.putSigningSession('ss-u1', rec as any, 10_000);

      const first = await signingSessionStore.takeSigningSession('ss-u1');
      const second = await signingSessionStore.takeSigningSession('ss-u1');

      expect(first?.mpcSessionId).toBe(rec.mpcSessionId);
      expect(second).toBeNull();
    });

    test('presignaturePool reserve/consume are single-use under concurrency', async () => {
      test.skip(!enabled, 'UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN not set');
      const { presignaturePool } = createThresholdEcdsaSigningStores({
        config: {
          kind: 'upstash-redis-rest',
          UPSTASH_REDIS_REST_URL: upstashUrl,
          UPSTASH_REDIS_REST_TOKEN: upstashToken,
          THRESHOLD_ECDSA_SIGNING_PREFIX: signingPrefix,
          THRESHOLD_ECDSA_PRESIGN_PREFIX: presignPrefix,
        } as any,
        logger: console as any,
        isNode: true,
      });

      const relayerKeyId = 'rk-u2';
      await presignaturePool.put(makePresignRecord({ relayerKeyId, presignatureId: 'ps-ua', createdAtMs: Date.now() - 2 }) as any);
      await presignaturePool.put(makePresignRecord({ relayerKeyId, presignatureId: 'ps-ub', createdAtMs: Date.now() - 1 }) as any);

      const [a, b] = await Promise.all([presignaturePool.reserve(relayerKeyId), presignaturePool.reserve(relayerKeyId)]);
      expect(a && b).toBeTruthy();
      expect(a!.presignatureId).not.toBe(b!.presignatureId);

      const a1 = await presignaturePool.consume(relayerKeyId, a!.presignatureId);
      const a2 = await presignaturePool.consume(relayerKeyId, a!.presignatureId);
      expect(a1?.presignatureId).toBe(a!.presignatureId);
      expect(a2).toBeNull();

      const b1 = await presignaturePool.consume(relayerKeyId, b!.presignatureId);
      const b2 = await presignaturePool.consume(relayerKeyId, b!.presignatureId);
      expect(b1?.presignatureId).toBe(b!.presignatureId);
      expect(b2).toBeNull();
    });

    test('presignSessionStore CAS transitions are atomic', async () => {
      test.skip(!enabled, 'UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN not set');
      const { presignSessionStore } = createThresholdEcdsaSigningStores({
        config: {
          kind: 'upstash-redis-rest',
          UPSTASH_REDIS_REST_URL: upstashUrl,
          UPSTASH_REDIS_REST_TOKEN: upstashToken,
          THRESHOLD_ECDSA_SIGNING_PREFIX: signingPrefix,
          THRESHOLD_ECDSA_PRESIGN_PREFIX: presignPrefix,
        } as any,
        logger: console as any,
        isNode: true,
      });

      const created = await presignSessionStore.createSession(
        'psess-u1',
        makePresignSessionRecord({ version: 1, stage: 'triples' }) as any,
        10_000,
      );
      expect(created.ok).toBe(true);

      const stale = await presignSessionStore.advanceSessionCas({
        id: 'psess-u1',
        expectedVersion: 99,
        nextRecord: makePresignSessionRecord({ version: 100, stage: 'triples' }) as any,
        ttlMs: 10_000,
      });
      expect(stale.ok).toBe(false);
      if (!stale.ok) expect(stale.code).toBe('version_mismatch');

      const [a, b] = await Promise.all([
        presignSessionStore.advanceSessionCas({
          id: 'psess-u1',
          expectedVersion: 1,
          nextRecord: makePresignSessionRecord({ version: 2, stage: 'triples_done' }) as any,
          ttlMs: 10_000,
        }),
        presignSessionStore.advanceSessionCas({
          id: 'psess-u1',
          expectedVersion: 1,
          nextRecord: makePresignSessionRecord({ version: 2, stage: 'triples_done' }) as any,
          ttlMs: 10_000,
        }),
      ]);

      const oks = [a, b].filter((r) => r.ok);
      const errs = [a, b].filter((r) => !r.ok);
      expect(oks.length).toBe(1);
      expect(errs.length).toBe(1);
      if (!errs[0].ok) expect(errs[0].code).toBe('version_mismatch');

      const got = await presignSessionStore.getSession('psess-u1');
      expect(got?.version).toBe(2);
      expect(got?.stage).toBe('triples_done');

      await presignSessionStore.deleteSession('psess-u1');
      const afterDelete = await presignSessionStore.getSession('psess-u1');
      expect(afterDelete).toBeNull();
    });
  });
});
