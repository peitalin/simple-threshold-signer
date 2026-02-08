import { test, expect } from '@playwright/test';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import { callCf, makeCfCtx, makeFakeAuthService, makeSessionAdapter } from './helpers';

function validLoginOptionsBody(overrides?: Partial<any>): any {
  return {
    user_id: 'bob.testnet',
    rp_id: 'example.localhost',
    ...overrides,
  };
}

function validLoginVerifyBody(overrides?: Partial<any>): any {
  return {
    sessionKind: 'jwt',
    challengeId: 'challenge-123',
    webauthn_authentication: { ok: true, ...(overrides?.webauthn_authentication || {}) },
    ...overrides,
  };
}

test.describe('relayer router (cloudflare) – P0', () => {
  test('CORS preflight: allowlist echoes Origin + allows credentials', async () => {
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'] });

    const res = await callCf(handler, {
      method: 'OPTIONS',
      path: '/auth/passkey/verify',
      origin: 'https://example.localhost',
    });

    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-origin')).toBe('https://example.localhost');
    expect(res.headers.get('access-control-allow-credentials')).toBe('true');
    expect(res.headers.get('access-control-allow-methods')).toContain('OPTIONS');
    expect(res.headers.get('access-control-allow-headers')).toContain('Authorization');
    expect(res.headers.get('vary')).toContain('Origin');
  });

  test('CORS preflight: "*" allows origin but not credentials', async () => {
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, { corsOrigins: [] });

    const res = await callCf(handler, {
      method: 'OPTIONS',
      path: '/auth/passkey/verify',
      origin: 'https://example.localhost',
    });

    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
    expect(res.headers.get('access-control-allow-credentials')).toBe(null);
  });

  test('POST /auth/passkey/options: invalid body', async () => {
    const service = makeFakeAuthService({
      createWebAuthnLoginOptions: async () => ({ ok: false, code: 'invalid_body', message: 'Missing user_id' }),
    });
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'] });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/auth/passkey/options',
      origin: 'https://example.localhost',
      body: {},
    });

    expect(res.status).toBe(400);
    expect(res.json?.code).toBe('invalid_body');
  });

  test('POST /auth/passkey/options: ok returns challengeId', async () => {
    const service = makeFakeAuthService({
      createWebAuthnLoginOptions: async () => ({
        ok: true,
        challengeId: 'cid-123',
        challengeB64u: 'challenge-b64u',
        expiresAtMs: 123,
      }),
    });
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'] });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/auth/passkey/options',
      origin: 'https://example.localhost',
      body: validLoginOptionsBody(),
    });

    expect(res.status).toBe(200);
    expect(res.json?.challengeId).toBe('cid-123');
  });

  test('POST /auth/passkey/verify: invalid body', async () => {
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'] });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/auth/passkey/verify',
      origin: 'https://example.localhost',
      body: {},
    });

    expect(res.status).toBe(400);
    expect(res.json?.code).toBe('invalid_body');
  });

  test('POST /auth/passkey/verify: not verified maps to 400', async () => {
    const service = makeFakeAuthService({
      verifyWebAuthnLogin: async () => ({ ok: false, verified: false, code: 'not_verified', message: 'nope' }),
    });
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'] });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/auth/passkey/verify',
      origin: 'https://example.localhost',
      body: validLoginVerifyBody(),
    });

    expect(res.status).toBe(400);
    expect(res.json?.code).toBe('not_verified');
  });

  test('POST /auth/passkey/verify: verified + sessionKind=jwt returns jwt', async () => {
    const session = makeSessionAdapter({ signJwt: async () => 'jwt-123' });
    const service = makeFakeAuthService({
      verifyWebAuthnLogin: async () => ({ ok: true, verified: true, userId: 'bob.testnet', rpId: 'example.localhost' }),
    });
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'], session });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/auth/passkey/verify',
      origin: 'https://example.localhost',
      body: validLoginVerifyBody({ sessionKind: 'jwt' }),
    });

    expect(res.status).toBe(200);
    expect(res.json?.jwt).toBe('jwt-123');
  });

  test('POST /auth/passkey/verify: verified + sessionKind=cookie sets Set-Cookie and does not include jwt', async () => {
    const session = makeSessionAdapter({
      signJwt: async () => 'cookie-456',
      buildSetCookie: (t) => `w3a_session=${t}; Path=/; HttpOnly`,
    });
    const service = makeFakeAuthService({
      verifyWebAuthnLogin: async () => ({ ok: true, verified: true, userId: 'bob.testnet', rpId: 'example.localhost' }),
    });
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'], session });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/auth/passkey/verify',
      origin: 'https://example.localhost',
      body: validLoginVerifyBody({ sessionKind: 'cookie' }),
    });

    expect(res.status).toBe(200);
    expect(res.headers.get('set-cookie')).toContain('w3a_session=cookie-456');
    expect(res.json?.jwt).toBeUndefined();
  });

  test('POST /auth/passkey/verify: session failures are best-effort (still 200)', async () => {
    const session = makeSessionAdapter({
      signJwt: async () => { throw new Error('boom'); },
    });
    const service = makeFakeAuthService({
      verifyWebAuthnLogin: async () => ({ ok: true, verified: true, userId: 'bob.testnet', rpId: 'example.localhost' }),
    });
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'], session });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/auth/passkey/verify',
      origin: 'https://example.localhost',
      body: validLoginVerifyBody({ sessionKind: 'jwt' }),
    });

    expect(res.status).toBe(200);
    expect(res.json?.verified).toBe(true);
    expect(res.json?.jwt).toBeUndefined();
  });

  test('GET /session/auth: sessions disabled -> 501', async () => {
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'] });

    const res = await callCf(handler, {
      method: 'GET',
      path: '/session/auth',
      origin: 'https://example.localhost',
    });

    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('sessions_disabled');
    expect(res.json?.authenticated).toBe(false);
  });

  test('GET /session/auth: invalid session -> 401', async () => {
    const session = makeSessionAdapter({ parse: async () => ({ ok: false }) });
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'], session });

    const res = await callCf(handler, { method: 'GET', path: '/session/auth', origin: 'https://example.localhost' });

    expect(res.status).toBe(401);
    expect(res.json?.authenticated).toBe(false);
  });

  test('POST /session/refresh: unauthorized maps to 401', async () => {
    const session = makeSessionAdapter({ refresh: async () => ({ ok: false, code: 'unauthorized', message: 'no token' }) });
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'], session });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/session/refresh',
      origin: 'https://example.localhost',
      body: { sessionKind: 'jwt' },
    });

    expect(res.status).toBe(401);
    expect(res.json?.code).toBe('unauthorized');
  });

  test('POST /session/logout: sets clear cookie when sessions enabled', async () => {
    const session = makeSessionAdapter({
      buildClearCookie: () => 'w3a_session=; Path=/; Max-Age=0',
    });
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'], session });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/session/logout',
      origin: 'https://example.localhost',
    });

    expect(res.status).toBe(200);
    expect(res.json?.success).toBe(true);
    expect(res.headers.get('set-cookie')).toContain('Max-Age=0');
  });

  test('POST /recover-email: async mode uses ctx.waitUntil and returns 202 queued', async () => {
    const { ctx, waited } = makeCfCtx();
    const emailRecovery = {
      requestEmailRecovery: async () => ({ success: true, transactionHash: 'tx' }),
    };
    const service = makeFakeAuthService({ emailRecovery });
    const handler = createCloudflareRouter(service, { corsOrigins: ['https://example.localhost'] });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/recover-email?async=1',
      origin: 'https://example.localhost',
      body: {
        from: 'sender@example.com',
        to: 'recover@web3authn.org',
        headers: { Subject: 'recover-ABC123 bob.testnet ed25519:pk' },
        raw: 'Subject: recover-ABC123 bob.testnet ed25519:pk\r\n\r\nzk-email',
        rawSize: 1,
      },
      ctx,
    });

    expect(res.status).toBe(202);
    expect(res.json?.queued).toBe(true);
    expect(waited.length).toBe(1);
  });
});
