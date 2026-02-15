import { toAccountId, type AccountId } from '../../types/accountIds';
import type { SigningSessionStatus } from '../../types/tatchi';
import type { SecureConfirmWorkerManager } from '../secureConfirm/manager';

export type SigningSessionPolicyArgs = { ttlMs?: number; remainingUses?: number };
export type SigningSessionPolicy = { ttlMs: number; remainingUses: number };

export type SigningSessionStateDeps = {
  activeSigningSessionIds: Map<string, string>;
  secureConfirmWorkerManager: Pick<SecureConfirmWorkerManager, 'peekPrfFirstForThresholdSession'>;
  createSessionId: (prefix: string) => string;
  signingSessionDefaults: SigningSessionPolicy;
};

function toNonNegativeInt(value: unknown): number | undefined {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return undefined;
  return Math.floor(value);
}

export function generateSessionId(prefix: string): string {
  return typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function resolveSigningSessionPolicy(
  deps: SigningSessionStateDeps,
  args: SigningSessionPolicyArgs,
): SigningSessionPolicy {
  const ttlMs = toNonNegativeInt(args.ttlMs) ?? deps.signingSessionDefaults.ttlMs;
  const remainingUses =
    toNonNegativeInt(args.remainingUses) ?? deps.signingSessionDefaults.remainingUses;
  return { ttlMs, remainingUses };
}

export function getOrCreateActiveSigningSessionId(
  deps: SigningSessionStateDeps,
  nearAccountId: AccountId,
): string {
  const key = String(toAccountId(nearAccountId));
  const existing = deps.activeSigningSessionIds.get(key);
  if (existing) return existing;
  const sessionId = deps.createSessionId('signing-session');
  deps.activeSigningSessionIds.set(key, sessionId);
  return sessionId;
}

export async function getWarmSigningSessionStatus(
  deps: SigningSessionStateDeps,
  nearAccountId: AccountId | string,
): Promise<SigningSessionStatus | null> {
  try {
    const key = String(toAccountId(nearAccountId));
    const sessionId = deps.activeSigningSessionIds.get(key);
    if (!sessionId) return null;

    const peek = await deps.secureConfirmWorkerManager.peekPrfFirstForThresholdSession({ sessionId });
    if (peek.ok) {
      return {
        sessionId,
        status: 'active',
        remainingUses: peek.remainingUses,
        expiresAtMs: peek.expiresAtMs,
      };
    }

    let status: SigningSessionStatus['status'] = 'not_found';
    if (peek.code === 'expired') {
      status = 'expired';
    } else if (peek.code === 'exhausted') {
      status = 'exhausted';
    }
    return { sessionId, status };
  } catch {
    return null;
  }
}
