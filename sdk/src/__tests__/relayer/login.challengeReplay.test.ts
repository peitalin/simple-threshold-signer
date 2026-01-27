import { test, expect } from '@playwright/test';
import { AuthService } from '../../server/core/AuthService';
import { createRelayRouter } from '../../server/router/express-adaptor';
import { fetchJson, makeSessionAdapter, startExpressRouter } from './helpers';
import { DEFAULT_TEST_CONFIG } from '../setup/config';

test.describe('relayer login challenge replay', () => {
  test('POST /login/verify: replayed challengeId is rejected', async () => {
    const service = new AuthService({
      relayerAccountId: 'relayer.testnet',
      relayerPrivateKey: 'ed25519:dummy',
      webAuthnContractId: DEFAULT_TEST_CONFIG.contractId,
      nearRpcUrl: DEFAULT_TEST_CONFIG.nearRpcUrl,
      networkId: DEFAULT_TEST_CONFIG.nearNetwork,
      accountInitialBalance: '1',
      createAccountAndRegisterGas: '1',
      logger: null,
    });

    // Keep the test focused on challenge replay protection (store.consume).
    (service as unknown as {
      verifyWebAuthnAuthenticationLite: (req: unknown) => Promise<{ success: boolean; verified: boolean }>;
    }).verifyWebAuthnAuthenticationLite = async (_req: unknown) => ({ success: true, verified: true });

    const session = makeSessionAdapter({ signJwt: async () => 'jwt-123' });
    const router = createRelayRouter(service, { session });
    const srv = await startExpressRouter(router);

    try {
      const options = await fetchJson(`${srv.baseUrl}/login/options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: 'bob.testnet', rp_id: 'example.localhost' }),
      });
      expect(options.status).toBe(200);
      const challengeId = String(options.json?.challengeId || '');
      expect(challengeId.length).toBeGreaterThan(10);

      const verify1 = await fetchJson(`${srv.baseUrl}/login/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionKind: 'jwt', challengeId, webauthn_authentication: { ok: true } }),
      });
      expect(verify1.status).toBe(200);
      expect(verify1.json?.verified).toBe(true);
      expect(verify1.json?.jwt).toBe('jwt-123');

      const verify2 = await fetchJson(`${srv.baseUrl}/login/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionKind: 'jwt', challengeId, webauthn_authentication: { ok: true } }),
      });
      expect(verify2.status).toBe(400);
      expect(verify2.json?.code).toBe('challenge_expired_or_invalid');
      expect(verify2.json?.verified).toBe(false);
    } finally {
      await srv.close();
    }
  });
});
