import { test, expect } from '@playwright/test';
import { createRelayRouter } from '@server/router/express-adaptor';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import {
  THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
  THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
} from '@server/core/ThresholdService/schemes/schemeIds';
import { callCf, fetchJson, makeFakeAuthService, startExpressRouter } from './helpers';

function makeThresholdAdapter(module: unknown) {
  const requestedSchemeIds: string[] = [];
  return {
    requestedSchemeIds,
    threshold: {
      getSchemeModule(schemeId: string) {
        requestedSchemeIds.push(schemeId);
        return module as any;
      },
    },
  };
}

function makeEd25519SchemeForSignInit(result: Record<string, unknown>) {
  const signInitBodies: Array<Record<string, unknown>> = [];
  const scheme = {
    schemeId: THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID,
    healthz: async () => ({ ok: true }),
    keygen: async () => ({ ok: false, code: 'not_implemented', message: 'unused in test' }),
    session: async () => ({ ok: false, code: 'not_implemented', message: 'unused in test' }),
    authorize: async () => ({ ok: false, code: 'not_implemented', message: 'unused in test' }),
    protocol: {
      signInit: async (body: Record<string, unknown>) => {
        signInitBodies.push(body);
        return result;
      },
      signFinalize: async () => ({ ok: false, code: 'not_implemented', message: 'unused in test' }),
    },
  };
  return { scheme, signInitBodies };
}

test.describe('threshold-ed25519 scheme registry + dispatch coverage', () => {
  test('express: healthz returns not_found when ed25519 scheme module is not registered', async () => {
    const { requestedSchemeIds, threshold } = makeThresholdAdapter({
      schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
    });
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, { threshold: threshold as any });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/threshold-ed25519/healthz`, { method: 'GET' });
      expect(res.status).toBe(404);
      expect(res.json?.ok).toBe(false);
      expect(res.json?.code).toBe('not_found');
      expect(res.json?.message).toBe('threshold-ed25519 scheme is not enabled on this server');
      expect(requestedSchemeIds).toEqual([THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID]);
    } finally {
      await srv.close();
    }
  });

  test('express: sign/init dispatches through ed25519 protocol driver from scheme registry', async () => {
    const expected = { ok: true, signingSessionId: 'sign-ed25519-1' };
    const { scheme, signInitBodies } = makeEd25519SchemeForSignInit(expected);
    const { requestedSchemeIds, threshold } = makeThresholdAdapter(scheme);
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, { threshold: threshold as any });
    const srv = await startExpressRouter(router);
    try {
      const body = {
        mpcSessionId: 'mpc-1',
        relayerKeyId: 'ed25519:key-1',
        nearAccountId: 'alice.testnet',
        signingDigestB64u: Buffer.alloc(32, 7).toString('base64url'),
        clientCommitments: { hiding: 'h', binding: 'b' },
      };
      const res = await fetchJson(`${srv.baseUrl}/threshold-ed25519/sign/init`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      expect(res.status).toBe(200);
      expect(res.json).toEqual(expected);
      expect(signInitBodies).toEqual([body]);
      expect(requestedSchemeIds).toEqual([THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID]);
    } finally {
      await srv.close();
    }
  });

  test('cloudflare: healthz returns not_found when ed25519 scheme module is not registered', async () => {
    const { requestedSchemeIds, threshold } = makeThresholdAdapter({
      schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
    });
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, { threshold: threshold as any });
    const res = await callCf(handler, { method: 'GET', path: '/threshold-ed25519/healthz' });
    expect(res.status).toBe(404);
    expect(res.json?.ok).toBe(false);
    expect(res.json?.code).toBe('not_found');
    expect(res.json?.message).toBe('threshold-ed25519 scheme is not enabled on this server');
    expect(requestedSchemeIds).toEqual([THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID]);
  });

  test('cloudflare: sign/init dispatches through ed25519 protocol driver from scheme registry', async () => {
    const expected = { ok: true, signingSessionId: 'sign-ed25519-cf-1' };
    const { scheme, signInitBodies } = makeEd25519SchemeForSignInit(expected);
    const { requestedSchemeIds, threshold } = makeThresholdAdapter(scheme);
    const service = makeFakeAuthService();
    const handler = createCloudflareRouter(service, { threshold: threshold as any });

    const body = {
      mpcSessionId: 'mpc-2',
      relayerKeyId: 'ed25519:key-2',
      nearAccountId: 'bob.testnet',
      signingDigestB64u: Buffer.alloc(32, 9).toString('base64url'),
      clientCommitments: { hiding: 'h2', binding: 'b2' },
    };
    const res = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/sign/init',
      body,
    });

    expect(res.status).toBe(200);
    expect(res.json).toEqual(expected);
    expect(signInitBodies).toEqual([body]);
    expect(requestedSchemeIds).toEqual([THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID]);
  });
});
