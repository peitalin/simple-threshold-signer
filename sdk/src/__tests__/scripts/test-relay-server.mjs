#!/usr/bin/env node
import { createServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promises as fs } from 'node:fs';

// Import from built SDK to avoid TS transpilation for tests
import {
  AuthService,
  createThresholdSigningService,
} from '../../../dist/esm/server/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(path.join(__dirname, '../../..'));
const RELAY_DIR = path.join(ROOT, 'examples', 'relay-server');
const DEFAULT_CACHE = path.join(RELAY_DIR, '.provision-cache.json');
const CACHE_PATH = process.env.RELAY_PROVISION_CACHE_PATH || DEFAULT_CACHE;

async function readCache() {
  const txt = await fs.readFile(CACHE_PATH, 'utf8');
  return JSON.parse(txt);
}

async function main() {
  const cache = await readCache();

  const config = {
    relayerAccountId: cache.accountId,
    relayerPrivateKey: cache.nearPrivateKey,
    webAuthnContractId: 'w3a-v1.testnet',
    nearRpcUrl: process.env.NEAR_RPC_URL || 'https://test.rpc.fastnear.com',
    networkId: 'testnet',
    accountInitialBalance: '30000000000000000000000',
    createAccountAndRegisterGas: '85000000000000',
  };

  const authService = new AuthService(config);

  // Test harness: skip WebAuthn signature verification for relayer routes.
  // The Playwright suite validates client-side behavior; keeping the relay permissive avoids
  // failures caused by browser WebAuthn mock signature differences.
  try {
    authService.verifyWebAuthnAuthenticationLite = async () => ({ success: true, verified: true });
  } catch { }

  // Threshold signing services (in-memory stores are sufficient for test runs).
  const threshold = createThresholdSigningService({
    authService,
    thresholdEd25519KeyStore: { kind: 'in-memory' },
    logger: null,
  });

  // Default to 3001 to avoid conflicts with the example relay-server (which defaults to 3000).
  const port = Number(process.env.RELAY_PORT || '3001');
  const allowedOrigins = [
    process.env.EXPECTED_ORIGIN || 'https://example.localhost',
    process.env.EXPECTED_WALLET_ORIGIN || 'https://wallet.example.localhost',
  ].filter(Boolean);

  const setCors = (req, res) => {
    const requestOrigin = String(req.headers?.origin || '');
    const allowOrigin =
      requestOrigin && allowedOrigins.includes(requestOrigin)
        ? requestOrigin
        : (allowedOrigins[0] || '*');

    res.setHeader('Access-Control-Allow-Origin', allowOrigin);
    res.setHeader('Vary', 'Origin');
    if (allowOrigin !== '*') {
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  };

  const readJson = async (req) => new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => { data += chunk; });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });

  const sendJson = (res, status, body) => {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(body));
  };

  const thresholdStatus = (result) => {
    if (result?.ok) return 200;
    switch (result?.code) {
      case 'threshold_disabled':
        return 503;
      case 'internal':
        return 500;
      case 'unauthorized':
        return 401;
      default:
        return 400;
    }
  };

  const server = createServer(async (req, res) => {
    setCors(req, res);
    if (req.method === 'OPTIONS') {
      res.statusCode = 200; return res.end();
    }
    const url = new URL(req.url, `http://localhost:${port}`);
    try {
      if (req.method === 'GET' && url.pathname === '/healthz') {
        return sendJson(res, 200, { ok: true, relayerAccountId: cache.accountId, contractId: config.webAuthnContractId });
      }
      if (req.method === 'GET' && url.pathname === '/threshold-ed25519/healthz') {
        return sendJson(res, 200, { ok: true, configured: true });
      }
      if (req.method === 'POST' && url.pathname === '/login/options') {
        const body = await readJson(req);
        const out = await authService.createWebAuthnLoginOptions(body);
        if (!out?.ok) {
          return sendJson(res, out?.code === 'internal' ? 500 : 400, out);
        }
        return sendJson(res, 200, out);
      }
      if (req.method === 'POST' && url.pathname === '/login/verify') {
        const body = await readJson(req);
        const challengeId = String(body?.challengeId ?? body?.challenge_id ?? '').trim();
        if (!challengeId) {
          return sendJson(res, 400, { ok: false, code: 'invalid_body', message: 'challengeId is required' });
        }
        const authn = body?.webauthn_authentication;
        if (!authn || typeof authn !== 'object') {
          return sendJson(res, 400, { ok: false, code: 'invalid_body', message: 'webauthn_authentication is required' });
        }

        const origin = String(req.headers?.origin || req.headers?.Origin || '').trim() || undefined;
        const out = await authService.verifyWebAuthnLogin({
          challengeId,
          webauthn_authentication: authn,
          expected_origin: origin,
        });

        if (!out?.ok || !out?.verified) {
          return sendJson(res, out?.code === 'internal' ? 500 : 400, out);
        }

        const sessionKindRaw = String(body?.sessionKind ?? body?.session_kind ?? 'jwt').trim().toLowerCase();
        const sessionKind = sessionKindRaw === 'cookie' ? 'cookie' : 'jwt';
        if (sessionKind === 'jwt') {
          const token = `testjwt-${Date.now()}-${Math.random().toString(16).slice(2)}`;
          return sendJson(res, 200, { ok: true, verified: true, jwt: token });
        }
        return sendJson(res, 200, { ok: true, verified: true });
      }
      if (req.method === 'POST' && url.pathname === '/threshold-ed25519/keygen') {
        const body = await readJson(req);
        const out = await threshold.thresholdEd25519Keygen(body);
        return sendJson(res, thresholdStatus(out), out);
      }
      if (req.method === 'POST' && url.pathname === '/create_account_and_register_user') {
        const body = await readJson(req);
        const {
          new_account_id,
          new_public_key: requested_public_key,
          threshold_ed25519,
          device_number,
          rp_id,
          webauthn_registration,
          authenticator_options
        } = body || {};

        const thresholdClientVerifyingShareB64u = String(threshold_ed25519?.client_verifying_share_b64u || '').trim();
        let new_public_key = String(requested_public_key || '').trim();
        let thresholdEd25519 = null;

        if (!new_public_key && thresholdClientVerifyingShareB64u) {
          const out = await threshold.keygenFromClientVerifyingShareForRegistration({
            nearAccountId: new_account_id,
            rpId: rp_id,
            clientVerifyingShareB64u: thresholdClientVerifyingShareB64u,
          });
          if (!out.ok) {
            return sendJson(res, 400, { success: false, error: out.message || 'threshold keygen failed' });
          }
          // Persist key material before creating an account with the threshold key.
          await threshold.putRelayerKeyMaterial({
            relayerKeyId: out.relayerKeyId,
            publicKey: out.publicKey,
            relayerSigningShareB64u: out.relayerSigningShareB64u,
            relayerVerifyingShareB64u: out.relayerVerifyingShareB64u,
          });
          new_public_key = out.publicKey;
          thresholdEd25519 = {
            relayerKeyId: out.relayerKeyId,
            publicKey: out.publicKey,
            relayerVerifyingShareB64u: out.relayerVerifyingShareB64u,
            clientParticipantId: out.clientParticipantId,
            relayerParticipantId: out.relayerParticipantId,
            participantIds: out.participantIds,
          };
        }

        if (!new_account_id || !new_public_key || !rp_id || !webauthn_registration) {
          return sendJson(res, 400, { success: false, error: 'missing required fields' });
        }
        const expected_origin = String(req.headers?.origin || '').trim();
        const result = await authService.createAccountAndRegisterUser({
          new_account_id,
          new_public_key,
          device_number,
          threshold_ed25519,
          rp_id,
          webauthn_registration,
          ...(expected_origin ? { expected_origin } : {}),
          authenticator_options
        });
        const response = thresholdEd25519 && result?.success
          ? { ...result, thresholdEd25519 }
          : result;
        return sendJson(res, result.success ? 200 : 400, response);
      }
      sendJson(res, 404, { error: 'not_found' });
    } catch (e) {
      sendJson(res, 500, { error: 'internal', details: e?.message });
    }
  });

  server.listen(port, () => {
    console.log(`[test-relay] listening on http://localhost:${port}`);
  });
}

main().catch((e) => { console.error(e); process.exit(1); });
