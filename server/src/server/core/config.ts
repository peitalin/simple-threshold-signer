import type {
  AuthServiceConfig,
  AuthServiceConfigInput,
  GoogleOidcConfigEnvInput,
  ZkEmailProverConfigEnvInput,
} from './types';
import {
  THRESHOLD_ED25519_DO_OBJECT_NAME_DEFAULT,
  THRESHOLD_ED25519_SHARE_MODE_DEFAULT,
  THRESHOLD_PREFIX_DEFAULT,
} from './defaultConfigsServer';
import { toOptionalTrimmedString, toTrimmedString } from '@shared/utils/validation';

export const AUTH_SERVICE_CONFIG_DEFAULTS = {
  // Prefer FastNEAR for testnet by default (more reliable in practice).
  // If you set `networkId: 'mainnet'` and omit `nearRpcUrl`, the default switches to NEAR mainnet RPC.
  nearRpcUrlTestnet: 'https://test.rpc.fastnear.com',
  nearRpcUrlMainnet: 'https://rpc.mainnet.near.org',
  networkId: 'testnet',
  // 0.03 NEAR (typical for examples; adjust based on your app/storage needs).
  accountInitialBalance: '30000000000000000000000',
  // 85 TGas (tested)
  createAccountAndRegisterGas: '85000000000000',
} as const;

function defaultNearRpcUrl(networkId: string): string {
  const net = String(networkId || '').trim().toLowerCase();
  if (net === 'mainnet') return AUTH_SERVICE_CONFIG_DEFAULTS.nearRpcUrlMainnet;
  return AUTH_SERVICE_CONFIG_DEFAULTS.nearRpcUrlTestnet;
}

function normalizeZkEmailProverConfig(
  input: AuthServiceConfigInput['zkEmailProver'],
): AuthServiceConfig['zkEmailProver'] | undefined {
  if (!input) return undefined;

  // Full options object
  if (typeof (input as any).baseUrl === 'string') {
    const baseUrl = toOptionalTrimmedString((input as any).baseUrl);
    if (!baseUrl) return undefined;
    return input as AuthServiceConfig['zkEmailProver'];
  }

  // Env-shaped input
  const envInput = input as ZkEmailProverConfigEnvInput;
  const baseUrl = toOptionalTrimmedString(envInput.ZK_EMAIL_PROVER_BASE_URL);
  const timeoutMsRaw = toOptionalTrimmedString(envInput.ZK_EMAIL_PROVER_TIMEOUT_MS);

  const anyProvided = Boolean(baseUrl || timeoutMsRaw);
  if (!anyProvided) return undefined;
  if (!baseUrl) {
    throw new Error('zkEmailProver enabled but ZK_EMAIL_PROVER_BASE_URL is not set');
  }

  const timeoutMs = timeoutMsRaw ? Number(timeoutMsRaw) : undefined;
  if (timeoutMsRaw && (!Number.isFinite(timeoutMs) || timeoutMs! <= 0)) {
    throw new Error('ZK_EMAIL_PROVER_TIMEOUT_MS must be a positive integer (ms)');
  }

  return {
    baseUrl,
    timeoutMs,
  };
}

function parseCsv(input?: string | null): string[] {
  return String(input || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function normalizeGoogleOidcConfig(
  input: AuthServiceConfigInput['googleOidc'],
): AuthServiceConfig['googleOidc'] | undefined {
  if (!input) return undefined;

  // Full options object
  if (typeof input === 'object' && !Array.isArray(input) && Array.isArray((input as any).clientIds)) {
    const clientIds = Array.from(new Set(((input as any).clientIds as unknown[]).map((v) => String(v || '').trim()).filter(Boolean)));
    if (!clientIds.length) return undefined;
    const hostedDomains = Array.isArray((input as any).hostedDomains)
      ? Array.from(new Set(((input as any).hostedDomains as unknown[]).map((v) => String(v || '').trim().toLowerCase()).filter(Boolean)))
      : [];
    return {
      clientIds,
      ...(hostedDomains.length ? { hostedDomains } : {}),
    };
  }

  // Env-shaped input
  const envInput = input as GoogleOidcConfigEnvInput;
  const single = toOptionalTrimmedString(envInput.GOOGLE_OIDC_CLIENT_ID);
  const csv = toOptionalTrimmedString(envInput.GOOGLE_OIDC_CLIENT_IDS);
  const hostedRaw = toOptionalTrimmedString(envInput.GOOGLE_OIDC_HOSTED_DOMAINS);

  const anyProvided = Boolean(single || csv || hostedRaw);
  if (!anyProvided) return undefined;

  const clientIds = Array.from(new Set([...(single ? [single] : []), ...parseCsv(csv)]));
  if (!clientIds.length) {
    throw new Error('googleOidc enabled but GOOGLE_OIDC_CLIENT_ID(S) is not set');
  }

  const hostedDomains = hostedRaw
    ? Array.from(new Set(parseCsv(hostedRaw).map((d) => d.toLowerCase())))
    : [];

  return {
    clientIds,
    ...(hostedDomains.length ? { hostedDomains } : {}),
  };
}

function normalizeThresholdEd25519KeyStoreConfig(
  input: AuthServiceConfigInput['thresholdEd25519KeyStore'],
): AuthServiceConfig['thresholdEd25519KeyStore'] | undefined {
  if (!input) return undefined;
  if (typeof input !== 'object' || Array.isArray(input)) return undefined;

  const c = input as Record<string, unknown>;
  const anyProvided = Boolean(
    // Minimal (env-shaped)
    toOptionalTrimmedString(c.THRESHOLD_ED25519_SHARE_MODE)
    || toOptionalTrimmedString(c.THRESHOLD_ED25519_MASTER_SECRET_B64U)
    || toOptionalTrimmedString(c.THRESHOLD_SECP256K1_MASTER_SECRET_B64U)
    || toOptionalTrimmedString(c.THRESHOLD_NODE_ROLE)
    || toOptionalTrimmedString(c.THRESHOLD_COORDINATOR_SHARED_SECRET_B64U)
    || toOptionalTrimmedString(c.THRESHOLD_ED25519_RELAYER_COSIGNERS)
    || toOptionalTrimmedString(c.THRESHOLD_ED25519_RELAYER_COSIGNER_ID)
    || toOptionalTrimmedString(c.THRESHOLD_ED25519_RELAYER_COSIGNER_T)
    || toOptionalTrimmedString(c.THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID)
    || toOptionalTrimmedString(c.THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID)
    || toOptionalTrimmedString(c.THRESHOLD_PREFIX)
    || toOptionalTrimmedString(c.THRESHOLD_ED25519_AUTH_PREFIX)
    || toOptionalTrimmedString(c.THRESHOLD_ED25519_SESSION_PREFIX)
    || toOptionalTrimmedString(c.THRESHOLD_ED25519_KEYSTORE_PREFIX)
    || toOptionalTrimmedString(c.THRESHOLD_ECDSA_AUTH_PREFIX)
    || toOptionalTrimmedString(c.THRESHOLD_ECDSA_SESSION_PREFIX)
    || toOptionalTrimmedString(c.THRESHOLD_ECDSA_KEYSTORE_PREFIX)
    // Explicit store config (kind-shaped)
    || toOptionalTrimmedString(c.kind)
    || toOptionalTrimmedString(c.url)
    || toOptionalTrimmedString(c.token)
    || toOptionalTrimmedString(c.redisUrl)
    || toOptionalTrimmedString(c.postgresUrl)
    // Env-shaped store toggles
    || toOptionalTrimmedString(c.UPSTASH_REDIS_REST_URL)
    || toOptionalTrimmedString(c.UPSTASH_REDIS_REST_TOKEN)
    || toOptionalTrimmedString(c.REDIS_URL)
    || toOptionalTrimmedString(c.POSTGRES_URL),
  );
  if (!anyProvided) return undefined;

  // Apply sane defaults for common serverless/Worker configurations.
  //
  // Note: never default `THRESHOLD_ED25519_MASTER_SECRET_B64U` — it is always explicitly provided as a secret.
  const normalized: Record<string, unknown> = { ...(input as Record<string, unknown>) };
  const kind = toOptionalTrimmedString(normalized.kind);
  if (kind === 'cloudflare-do') {
    const name = toOptionalTrimmedString(normalized.name);
    if (!name) normalized.name = THRESHOLD_ED25519_DO_OBJECT_NAME_DEFAULT;

    const thresholdPrefix = toOptionalTrimmedString(normalized.THRESHOLD_PREFIX);
    const anySpecificPrefix = Boolean(
      toOptionalTrimmedString(normalized.THRESHOLD_ED25519_AUTH_PREFIX)
      || toOptionalTrimmedString(normalized.THRESHOLD_ED25519_SESSION_PREFIX)
      || toOptionalTrimmedString(normalized.THRESHOLD_ED25519_KEYSTORE_PREFIX),
    );
    if (!thresholdPrefix && !anySpecificPrefix) {
      normalized.THRESHOLD_PREFIX = THRESHOLD_PREFIX_DEFAULT;
    }

    const shareMode = toOptionalTrimmedString(normalized.THRESHOLD_ED25519_SHARE_MODE);
    if (!shareMode) normalized.THRESHOLD_ED25519_SHARE_MODE = THRESHOLD_ED25519_SHARE_MODE_DEFAULT;
  }

  return normalized as AuthServiceConfig['thresholdEd25519KeyStore'];
}

export function createAuthServiceConfig(input: AuthServiceConfigInput): AuthServiceConfig {
  const networkId = toTrimmedString(input.networkId) || AUTH_SERVICE_CONFIG_DEFAULTS.networkId;
  const config: AuthServiceConfig = {
    relayerAccountId: toTrimmedString(input.relayerAccountId),
    relayerPrivateKey: toTrimmedString(input.relayerPrivateKey),
    webAuthnContractId: toTrimmedString(input.webAuthnContractId),
    nearRpcUrl: toTrimmedString(input.nearRpcUrl) || defaultNearRpcUrl(networkId),
    networkId: networkId,
    accountInitialBalance: toTrimmedString(input.accountInitialBalance)
      || AUTH_SERVICE_CONFIG_DEFAULTS.accountInitialBalance,
    createAccountAndRegisterGas: toTrimmedString(input.createAccountAndRegisterGas)
      || AUTH_SERVICE_CONFIG_DEFAULTS.createAccountAndRegisterGas,
    signerWasm: input.signerWasm,
    thresholdEd25519KeyStore: normalizeThresholdEd25519KeyStoreConfig(input.thresholdEd25519KeyStore),
    logger: input.logger,
    zkEmailProver: normalizeZkEmailProverConfig(input.zkEmailProver),
    googleOidc: normalizeGoogleOidcConfig(input.googleOidc),
  };

  validateConfigs(config);
  return config;
}

export function validateConfigs(config: AuthServiceConfig): void {

  const requiredTop = ['relayerAccountId','relayerPrivateKey'] as const;
  for (const key of requiredTop) {
    if (!(config as any)[key]) throw new Error(`Missing required config variable: ${key}`);
  }

  // Validate private key format
  if (!config.relayerPrivateKey?.startsWith('ed25519:')) {
    throw new Error('Relayer private key must be in format "ed25519:base58privatekey"');
  }
}

export function parseBool(v: unknown): boolean {
  const s = String(v ?? '').trim().toLowerCase();
  return s === '1' || s === 'true' || s === 'yes' || s === 'on';
}

export function requireEnvVar<T extends object, K extends keyof T & string>(env: T, name: K): string {
  const raw = (env as any)?.[name] as unknown;
  if (typeof raw !== 'string') throw new Error(`Missing required env var: ${name}`);
  const v = raw.trim();
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}
