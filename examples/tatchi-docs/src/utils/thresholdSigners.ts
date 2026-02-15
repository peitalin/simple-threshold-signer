import type { TatchiPasskey } from '@tatchi-xyz/sdk/react';

export type ThresholdEcdsaBootstrapResult = Awaited<
  ReturnType<TatchiPasskey['bootstrapThresholdEcdsaSession']>
>;
export type ThresholdEcdsaKeyRef = ThresholdEcdsaBootstrapResult['thresholdEcdsaKeyRef'];
export type ThresholdEcdsaChain = 'evm' | 'tempo';

type ProvisionThresholdSignerForChainArgs = {
  tatchi: TatchiPasskey;
  nearAccountId: string;
  chain: ThresholdEcdsaChain;
  ttlMs?: number;
  remainingUses?: number;
};

type ResolveThresholdKeyRefArgs = ProvisionThresholdSignerForChainArgs & {
  forceReprovision?: boolean;
};

const CACHE_KEY_PREFIX = 'tatchi-docs:threshold-keyref:v1';
const DEFAULT_TTL_MS = 30 * 60 * 1000;
const DEFAULT_REMAINING_USES = 12;

function cacheKey(nearAccountId: string, chain: ThresholdEcdsaChain): string {
  return `${CACHE_KEY_PREFIX}:${nearAccountId}:${chain}`;
}

function toNonEmptyString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function isThresholdKeyRef(value: unknown): value is ThresholdEcdsaKeyRef {
  if (!value || typeof value !== 'object') return false;
  const obj = value as Record<string, unknown>;
  return (
    toNonEmptyString(obj.type) === 'threshold-ecdsa-secp256k1' &&
    toNonEmptyString(obj.userId).length > 0 &&
    toNonEmptyString(obj.relayerUrl).length > 0 &&
    toNonEmptyString(obj.relayerKeyId).length > 0 &&
    toNonEmptyString(obj.clientVerifyingShareB64u).length > 0
  );
}

function getStorage(): Storage | null {
  if (typeof window === 'undefined') return null;
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

export function readCachedThresholdKeyRef(
  nearAccountId: string,
  chain: ThresholdEcdsaChain,
): ThresholdEcdsaKeyRef | null {
  const storage = getStorage();
  if (!storage) return null;
  const key = cacheKey(nearAccountId, chain);
  const raw = storage.getItem(key);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    return isThresholdKeyRef(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export function writeCachedThresholdKeyRef(
  nearAccountId: string,
  chain: ThresholdEcdsaChain,
  keyRef: ThresholdEcdsaKeyRef,
): void {
  const storage = getStorage();
  if (!storage) return;
  const key = cacheKey(nearAccountId, chain);
  try {
    storage.setItem(key, JSON.stringify(keyRef));
  } catch {}
}

export async function provisionThresholdSignerForChain(
  args: ProvisionThresholdSignerForChainArgs,
): Promise<ThresholdEcdsaBootstrapResult> {
  const bootstrap = await args.tatchi.bootstrapThresholdEcdsaSession({
    nearAccountId: args.nearAccountId,
    options: {
      chain: args.chain,
      ttlMs: typeof args.ttlMs === 'number' ? args.ttlMs : DEFAULT_TTL_MS,
      remainingUses:
        typeof args.remainingUses === 'number' ? args.remainingUses : DEFAULT_REMAINING_USES,
    },
  });
  writeCachedThresholdKeyRef(args.nearAccountId, args.chain, bootstrap.thresholdEcdsaKeyRef);
  return bootstrap;
}

export async function provisionTempoAndEvmThresholdSigners(args: {
  tatchi: TatchiPasskey;
  nearAccountId: string;
  ttlMs?: number;
  remainingUses?: number;
}): Promise<{
  evm: ThresholdEcdsaBootstrapResult;
  tempo: ThresholdEcdsaBootstrapResult;
}> {
  const [evmResult, tempoResult] = await Promise.allSettled([
    provisionThresholdSignerForChain({
      tatchi: args.tatchi,
      nearAccountId: args.nearAccountId,
      chain: 'evm',
      ttlMs: args.ttlMs,
      remainingUses: args.remainingUses,
    }),
    provisionThresholdSignerForChain({
      tatchi: args.tatchi,
      nearAccountId: args.nearAccountId,
      chain: 'tempo',
      ttlMs: args.ttlMs,
      remainingUses: args.remainingUses,
    }),
  ]);

  if (evmResult.status === 'fulfilled' && tempoResult.status === 'fulfilled') {
    return {
      evm: evmResult.value,
      tempo: tempoResult.value,
    };
  }

  const messages: string[] = [];
  if (evmResult.status === 'rejected') {
    const message =
      evmResult.reason instanceof Error ? evmResult.reason.message : String(evmResult.reason);
    messages.push(`evm: ${message}`);
  }
  if (tempoResult.status === 'rejected') {
    const message =
      tempoResult.reason instanceof Error ? tempoResult.reason.message : String(tempoResult.reason);
    messages.push(`tempo: ${message}`);
  }

  throw new Error(`Threshold signer provisioning failed (${messages.join('; ')})`);
}

export async function resolveThresholdKeyRef(
  args: ResolveThresholdKeyRefArgs,
): Promise<ThresholdEcdsaKeyRef> {
  if (!args.forceReprovision) {
    const cached = readCachedThresholdKeyRef(args.nearAccountId, args.chain);
    if (cached) return cached;
  }
  const bootstrap = await provisionThresholdSignerForChain({
    tatchi: args.tatchi,
    nearAccountId: args.nearAccountId,
    chain: args.chain,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
  });
  return bootstrap.thresholdEcdsaKeyRef;
}
