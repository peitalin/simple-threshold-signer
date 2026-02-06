import express, { Express } from 'express';
import {
  AuthService,
  requireEnvVar,
  createThresholdSigningService,
} from '@tatchi-xyz/sdk/server';
import { createRelayRouter } from '@tatchi-xyz/sdk/server/router/express';

import dotenv from 'dotenv';
import jwtSession from './jwtSession.js';

dotenv.config();

let server: ReturnType<Express['listen']> | null = null;

function shutdown(signal: string) {
  console.log(`[shutdown] received ${signal}, closing server...`);
  if (!server) {
    process.exit(0);
  }
  server.close(() => {
    console.log('[shutdown] http server closed');
    process.exit(0);
  });
  setTimeout(() => {
    console.error('[shutdown] force exit after 10s');
    process.exit(1);
  }, 10_000).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

async function main() {
  const env = process.env;
  const config = {
    port: Number(env.PORT || 3000),
    expectedOrigin: env.EXPECTED_ORIGIN || 'https://example.localhost', // Frontend origin
    expectedWalletOrigin: env.EXPECTED_WALLET_ORIGIN || 'https://wallet.example.localhost', // Wallet origin (optional)
  };

  const thresholdEd25519KeyStore = {
    // Share mode + deterministic relayer share derivation (optional)
    THRESHOLD_ED25519_SHARE_MODE: env.THRESHOLD_ED25519_SHARE_MODE,
    THRESHOLD_ED25519_MASTER_SECRET_B64U: env.THRESHOLD_ED25519_MASTER_SECRET_B64U,
    // Node role + coordinator/cosigner wiring (optional)
    THRESHOLD_NODE_ROLE: env.THRESHOLD_NODE_ROLE,
    THRESHOLD_COORDINATOR_SHARED_SECRET_B64U: env.THRESHOLD_COORDINATOR_SHARED_SECRET_B64U,
    // Optional persistence for sessions/shares
    POSTGRES_URL: env.POSTGRES_URL,
    UPSTASH_REDIS_REST_URL: env.UPSTASH_REDIS_REST_URL,
    UPSTASH_REDIS_REST_TOKEN: env.UPSTASH_REDIS_REST_TOKEN,
    REDIS_URL: env.REDIS_URL,
    // Optional key prefixes (useful when sharing a single database)
    THRESHOLD_ED25519_KEYSTORE_PREFIX: env.THRESHOLD_ED25519_KEYSTORE_PREFIX,
    THRESHOLD_ED25519_SESSION_PREFIX: env.THRESHOLD_ED25519_SESSION_PREFIX,
    THRESHOLD_ED25519_AUTH_PREFIX: env.THRESHOLD_ED25519_AUTH_PREFIX,
  } as const;

  const authService = new AuthService({
    // new accounts with be created with this account: e.g. bob.{relayer-account-id}.near
    // you can make it the same account as the webauthn contract id.
    relayerAccountId: requireEnvVar(env, 'RELAYER_ACCOUNT_ID'),
    relayerPrivateKey: requireEnvVar(env, 'RELAYER_PRIVATE_KEY'),
    webAuthnContractId: env.WEBAUTHN_CONTRACT_ID || 'w3a-v1.testnet',
    // Optional overrides (SDK provides defaults when omitted)
    nearRpcUrl: env.NEAR_RPC_URL,
    networkId: env.NETWORK_ID,
    accountInitialBalance: env.ACCOUNT_INITIAL_BALANCE,
    createAccountAndRegisterGas: env.CREATE_ACCOUNT_AND_REGISTER_GAS,
    logger: console,
    thresholdEd25519KeyStore,
    zkEmailProver: {
      ZK_EMAIL_PROVER_BASE_URL: env.ZK_EMAIL_PROVER_BASE_URL,
      ZK_EMAIL_PROVER_TIMEOUT_MS: env.ZK_EMAIL_PROVER_TIMEOUT_MS,
    },
    googleOidc: {
      GOOGLE_OIDC_CLIENT_ID: env.GOOGLE_OIDC_CLIENT_ID,
      GOOGLE_OIDC_CLIENT_IDS: env.GOOGLE_OIDC_CLIENT_IDS,
      GOOGLE_OIDC_HOSTED_DOMAINS: env.GOOGLE_OIDC_HOSTED_DOMAINS,
    },
  });

  await authService.initStorage();

  const threshold = createThresholdSigningService({
    authService,
    thresholdEd25519KeyStore,
    logger: console,
  });

  const app: Express = express();

  app.use((_req, res, next) => {
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('permissions-policy', 'geolocation=(), microphone=(), camera=()');
    next();
  });

  app.use(express.json({ limit: '1mb' }));

  // Mount router built from AuthService
  app.use('/', createRelayRouter(authService, {
    healthz: true,
    readyz: true,
    corsOrigins: [config.expectedOrigin, config.expectedWalletOrigin],
    signedDelegate: { route: '/signed-delegate' },
    session: jwtSession,
    threshold,
    logger: console,
  }));

  server = app.listen(config.port, () => {
    console.log(`Server listening on http://localhost:${config.port}`);
    console.log(`Expected Frontend Origin: ${config.expectedOrigin}`);
    authService.getRelayerAccount()
      .then(relayer => console.log(`AuthService started with relayer account: ${relayer.accountId}`))
      .catch((err: Error) => console.error('AuthService initial check failed:', err));
  });
}

main().catch((err) => {
  console.error('[relay-server] fatal startup error:', err);
  process.exit(1);
});
