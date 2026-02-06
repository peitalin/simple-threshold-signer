import { test, expect } from '@playwright/test';
import { createRelayRouter } from '../../server/router/express-adaptor';
import { fetchJson, getPath, makeFakeAuthService, makeSessionAdapter, startExpressRouter } from './helpers';

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

test.describe('relayer router (express) – P0', () => {
  test('POST /auth/passkey/options: invalid body', async () => {
    const service = makeFakeAuthService({
      createWebAuthnLoginOptions: async () => ({ ok: false, code: 'invalid_body', message: 'Missing user_id' }),
    });
    const router = createRelayRouter(service, {});
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/auth/passkey/options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(400);
      expect(res.json?.code).toBe('invalid_body');
    } finally {
      await srv.close();
    }
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
    const router = createRelayRouter(service, {});
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/auth/passkey/options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validLoginOptionsBody()),
      });
      expect(res.status).toBe(200);
      expect(res.json?.challengeId).toBe('cid-123');
    } finally {
      await srv.close();
    }
  });

  test('POST /auth/passkey/verify: invalid body', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {});
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/auth/passkey/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(400);
      expect(res.json?.code).toBe('invalid_body');
    } finally {
      await srv.close();
    }
  });

  test('POST /auth/passkey/verify: not verified maps to 400', async () => {
    const service = makeFakeAuthService({
      verifyWebAuthnLogin: async () => ({ ok: false, verified: false, code: 'not_verified', message: 'nope' }),
    });
    const router = createRelayRouter(service, {});
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/auth/passkey/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validLoginVerifyBody()),
      });
      expect(res.status).toBe(400);
      expect(res.json?.code).toBe('not_verified');
    } finally {
      await srv.close();
    }
  });

  test('POST /auth/passkey/verify: verified + sessionKind=jwt returns jwt', async () => {
    const session = makeSessionAdapter({ signJwt: async () => 'jwt-123' });
    const service = makeFakeAuthService({
      verifyWebAuthnLogin: async () => ({ ok: true, verified: true, userId: 'bob.testnet', rpId: 'example.localhost' }),
    });
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/auth/passkey/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validLoginVerifyBody({ sessionKind: 'jwt' })),
      });
      expect(res.status).toBe(200);
      expect(res.json?.jwt).toBe('jwt-123');
    } finally {
      await srv.close();
    }
  });

  test('POST /auth/passkey/verify: verified + sessionKind=cookie sets Set-Cookie and omits jwt', async () => {
    const session = makeSessionAdapter({
      signJwt: async () => 'cookie-456',
      buildSetCookie: (t) => `w3a_session=${t}; Path=/; HttpOnly`,
    });
    const service = makeFakeAuthService({
      verifyWebAuthnLogin: async () => ({ ok: true, verified: true, userId: 'bob.testnet', rpId: 'example.localhost' }),
    });
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/auth/passkey/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validLoginVerifyBody({ sessionKind: 'cookie' })),
      });
      expect(res.status).toBe(200);
      expect(res.headers.get('set-cookie')).toContain('w3a_session=cookie-456');
      expect(res.json?.jwt).toBeUndefined();
    } finally {
      await srv.close();
    }
  });

  test('POST /auth/passkey/verify: session issuance failures are best-effort', async () => {
    const session = makeSessionAdapter({
      signJwt: async () => { throw new Error('boom'); },
    });
    const service = makeFakeAuthService({
      verifyWebAuthnLogin: async () => ({ ok: true, verified: true, userId: 'bob.testnet', rpId: 'example.localhost' }),
    });
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/auth/passkey/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validLoginVerifyBody({ sessionKind: 'jwt' })),
      });
      expect(res.status).toBe(200);
      expect(res.json?.verified).toBe(true);
      expect(res.json?.jwt).toBeUndefined();
    } finally {
      await srv.close();
    }
  });

  test('GET /session/auth: sessions disabled -> 501', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {});
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/auth`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('sessions_disabled');
      expect(res.json?.authenticated).toBe(false);
    } finally {
      await srv.close();
    }
  });

  test('GET /session/auth: valid session -> 200 with claims', async () => {
    const session = makeSessionAdapter({
      parse: async () => ({ ok: true, claims: { sub: 'bob.testnet' } }),
    });
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/auth`, { method: 'GET' });
      expect(res.status).toBe(200);
      expect(res.json?.authenticated).toBe(true);
      expect(getPath(res.json, 'claims', 'sub')).toBe('bob.testnet');
    } finally {
      await srv.close();
    }
  });

  test('POST /session/refresh: cookie session sets Set-Cookie and returns { ok: true }', async () => {
    const session = makeSessionAdapter({
      parse: async () => ({ ok: true, claims: { sub: 'bob.testnet', kind: 'app_session_v1' } }),
      refresh: async () => ({ ok: true, jwt: 'refreshed-999' }),
      buildSetCookie: (t) => `w3a_session=${t}; Path=/; HttpOnly`,
    });
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionKind: 'cookie' }),
      });
      expect(res.status).toBe(200);
      expect(res.headers.get('set-cookie')).toContain('w3a_session=refreshed-999');
      expect(res.json?.ok).toBe(true);
      expect(res.json?.jwt).toBeUndefined();
    } finally {
      await srv.close();
    }
  });

  test('POST /session/refresh: unauthorized maps to 401', async () => {
    const session = makeSessionAdapter({
      refresh: async () => ({ ok: false, code: 'unauthorized', message: 'no token' }),
    });
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionKind: 'jwt' }),
      });
      expect(res.status).toBe(401);
      expect(res.json?.code).toBe('unauthorized');
    } finally {
      await srv.close();
    }
  });

  test('POST /session/logout: sets clear cookie when sessions enabled', async () => {
    const session = makeSessionAdapter({
      buildClearCookie: () => 'w3a_session=; Path=/; Max-Age=0',
    });
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/session/logout`, { method: 'POST' });
      expect(res.status).toBe(200);
      expect(res.json?.success).toBe(true);
      expect(res.headers.get('set-cookie')).toContain('Max-Age=0');
    } finally {
      await srv.close();
    }
  });

  test('custom sessionRoutes: auth/logout paths are honored', async () => {
    const session = makeSessionAdapter({
      parse: async () => ({ ok: true, claims: { sub: 'bob.testnet' } }),
      buildClearCookie: () => 'w3a_session=; Path=/; Max-Age=0',
    });
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, { session, sessionRoutes: { auth: '/me', logout: '/bye' } });
    const srv = await startExpressRouter(router);
    try {
      const me = await fetchJson(`${srv.baseUrl}/me`, { method: 'GET' });
      expect(me.status).toBe(200);
      expect(me.json?.authenticated).toBe(true);

      const out = await fetchJson(`${srv.baseUrl}/bye`, { method: 'POST' });
      expect(out.status).toBe(200);
      expect(out.json?.success).toBe(true);
      expect(out.headers.get('set-cookie')).toContain('Max-Age=0');
    } finally {
      await srv.close();
    }
  });
});
