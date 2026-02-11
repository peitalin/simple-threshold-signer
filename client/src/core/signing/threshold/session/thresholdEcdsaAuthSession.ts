import { stripTrailingSlashes, toTrimmedString } from '../../../../../../shared/src/utils/validation';
import type { ThresholdEcdsaSessionPolicy } from './thresholdSessionPolicy';
import type { WebAuthnAuthenticationCredential } from '../../../types/webauthn';
import { normalizeThresholdEd25519ParticipantIds } from '../../../../../../shared/src/threshold/participants';
import { redactCredentialExtensionOutputs } from '../ports/webauthn';

export type ThresholdEcdsaSessionKind = 'jwt' | 'cookie';

export type ThresholdEcdsaAuthSession = {
  sessionKind: ThresholdEcdsaSessionKind;
  policy: ThresholdEcdsaSessionPolicy;
  policyJson: string;
  sessionPolicyDigest32: string;
  jwt?: string;
  expiresAtMs?: number;
};

type ThresholdEcdsaAuthSessionCacheEntry = ThresholdEcdsaAuthSession;

const authSessionCache = new Map<string, ThresholdEcdsaAuthSessionCacheEntry>();

export function makeThresholdEcdsaAuthSessionCacheKey(args: {
  userId: string;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds?: number[];
}): string {
  const relayerUrl = stripTrailingSlashes(toTrimmedString(args.relayerUrl));
  const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds);
  return [
    String(args.userId || '').trim(),
    String(args.rpId || '').trim(),
    relayerUrl,
    String(args.relayerKeyId || '').trim(),
    ...(participantIds ? [participantIds.join(',')] : []),
  ].join('|');
}

export function getCachedThresholdEcdsaAuthSession(cacheKey: string): ThresholdEcdsaAuthSession | null {
  const entry = authSessionCache.get(cacheKey);
  if (!entry) return null;

  if (typeof entry.expiresAtMs === 'number' && Number.isFinite(entry.expiresAtMs) && Date.now() >= entry.expiresAtMs) {
    authSessionCache.delete(cacheKey);
    return null;
  }

  return entry;
}

export function putCachedThresholdEcdsaAuthSession(cacheKey: string, entry: ThresholdEcdsaAuthSession): void {
  authSessionCache.set(cacheKey, entry);
}

export function clearCachedThresholdEcdsaAuthSession(cacheKey: string): void {
  authSessionCache.delete(cacheKey);
}

export function clearAllCachedThresholdEcdsaAuthSessions(): void {
  authSessionCache.clear();
}

export function getCachedThresholdEcdsaAuthSessionJwt(cacheKey: string): string | undefined {
  const cached = getCachedThresholdEcdsaAuthSession(cacheKey);
  const jwt = cached?.jwt;
  if (typeof jwt === 'string') {
    const trimmed = jwt.trim();
    if (trimmed) return trimmed;
  }
  if (cached) clearCachedThresholdEcdsaAuthSession(cacheKey);
  return undefined;
}

function parseExpiresAtMs(data: { expiresAtMs?: unknown; expiresAt?: unknown }): number | undefined {
  const expiresAtMs = (() => {
    const raw = data.expiresAtMs;
    if (raw == null) return undefined;
    const n = typeof raw === 'number' ? raw : Number(raw);
    return Number.isFinite(n) ? Math.floor(n) : undefined;
  })();
  if (expiresAtMs) return expiresAtMs;

  const raw = typeof data.expiresAt === 'string' ? Date.parse(data.expiresAt) : NaN;
  return Number.isFinite(raw) ? raw : undefined;
}

/**
 * Lite (WebAuthn-only) threshold session mint.
 *
 * The server verifies the WebAuthn assertion directly and binds the session to the
 * `sessionPolicyDigest32` by using it as the WebAuthn challenge bytes (base64url string).
 *
 * Notes:
 * - Callers must ensure the WebAuthn `challenge` equals the session policy digest.
 * - PRF outputs must never be sent to the relay; they should be used only in wallet origin.
 */
export async function mintThresholdEcdsaAuthSessionLite(args: {
  relayerUrl: string;
  sessionKind: ThresholdEcdsaSessionKind;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  sessionPolicy: ThresholdEcdsaSessionPolicy;
  webauthnAuthentication: WebAuthnAuthenticationCredential;
}): Promise<{
  ok: boolean;
  sessionId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  jwt?: string;
  code?: string;
  message?: string;
}> {
  const relayerUrl = stripTrailingSlashes(toTrimmedString(args.relayerUrl));
  if (!relayerUrl) {
    return { ok: false, code: 'invalid_args', message: 'Missing relayerUrl for threshold session mint' };
  }

  if (typeof fetch !== 'function') {
    return { ok: false, code: 'unsupported', message: 'fetch is not available for threshold session mint' };
  }

  // Never send PRF outputs to the relay.
  const webauthn_authentication = redactCredentialExtensionOutputs(args.webauthnAuthentication);

  type ThresholdEcdsaSessionMintResponseBody = Partial<{
    ok: boolean;
    sessionId: string;
    expiresAtMs: number;
    expiresAt: string;
    remainingUses: number;
    jwt: string;
    code: string;
    message: string;
  }>;

  try {
    const url = `${relayerUrl}/threshold-ecdsa/session`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: args.sessionKind === 'cookie' ? 'include' : 'omit',
      body: JSON.stringify({
        sessionKind: args.sessionKind,
        relayerKeyId: args.relayerKeyId,
        clientVerifyingShareB64u: args.clientVerifyingShareB64u,
        sessionPolicy: args.sessionPolicy,
        webauthn_authentication,
      }),
    });

    const data = (await response.json().catch(() => ({}))) as ThresholdEcdsaSessionMintResponseBody;
    if (!response.ok) {
      return {
        ok: false,
        code: data.code || 'http_error',
        message: data.message || `HTTP ${response.status}`,
      };
    }

    return {
      ok: data.ok === true,
      sessionId: data.sessionId,
      expiresAtMs: parseExpiresAtMs(data),
      remainingUses: data.remainingUses,
      jwt: data.jwt,
      ...(data.code ? { code: data.code } : {}),
      ...(data.message ? { message: data.message } : {}),
    };
  } catch (e: unknown) {
    const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || 'Failed to mint threshold session');
    return { ok: false, code: 'network_error', message: msg };
  }
}
