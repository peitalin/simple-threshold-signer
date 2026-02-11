import { stripTrailingSlashes, toTrimmedString } from '../../../../../../shared/src/utils/validation';
import type { ThresholdEd25519SessionPolicy } from './thresholdSessionPolicy';
import type { WebAuthnAuthenticationCredential } from '../../../types/webauthn';
import { normalizeThresholdEd25519ParticipantIds } from '../../../../../../shared/src/threshold/participants';
import { redactCredentialExtensionOutputs } from '../ports/webauthn';

export type ThresholdEd25519SessionKind = 'jwt' | 'cookie';

export type ThresholdEd25519AuthSession = {
  sessionKind: ThresholdEd25519SessionKind;
  policy: ThresholdEd25519SessionPolicy;
  policyJson: string;
  sessionPolicyDigest32: string;
  jwt?: string;
  expiresAtMs?: number;
};

type ThresholdEd25519AuthSessionCacheEntry = ThresholdEd25519AuthSession;

const authSessionCache = new Map<string, ThresholdEd25519AuthSessionCacheEntry>();

export function makeThresholdEd25519AuthSessionCacheKey(args: {
  nearAccountId: string;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds?: number[];
}): string {
  const relayerUrl = stripTrailingSlashes(toTrimmedString(args.relayerUrl));
  const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds);
  return [
    String(args.nearAccountId || '').trim(),
    String(args.rpId || '').trim(),
    relayerUrl,
    String(args.relayerKeyId || '').trim(),
    ...(participantIds ? [participantIds.join(',')] : []),
  ].join('|');
}

export function getCachedThresholdEd25519AuthSession(cacheKey: string): ThresholdEd25519AuthSession | null {
  const entry = authSessionCache.get(cacheKey);
  if (!entry) return null;

  if (typeof entry.expiresAtMs === 'number' && Number.isFinite(entry.expiresAtMs) && Date.now() >= entry.expiresAtMs) {
    authSessionCache.delete(cacheKey);
    return null;
  }

  return entry;
}

export function putCachedThresholdEd25519AuthSession(cacheKey: string, entry: ThresholdEd25519AuthSession): void {
  authSessionCache.set(cacheKey, entry);
}

export function clearCachedThresholdEd25519AuthSession(cacheKey: string): void {
  authSessionCache.delete(cacheKey);
}

export function clearAllCachedThresholdEd25519AuthSessions(): void {
  authSessionCache.clear();
}

export function getCachedThresholdEd25519AuthSessionJwt(cacheKey: string): string | undefined {
  const cached = getCachedThresholdEd25519AuthSession(cacheKey);
  const jwt = cached?.jwt;
  if (typeof jwt === 'string') {
    const trimmed = jwt.trim();
    if (trimmed) return trimmed;
  }
  if (cached) clearCachedThresholdEd25519AuthSession(cacheKey);
  return undefined;
}

/**
 * Lite (WebAuthn-only) threshold session mint.
 *
 * The server verifies the WebAuthn assertion directly and binds the session to the
 * `sessionPolicyDigest32` by using it as the WebAuthn challenge bytes (base64url string).
 *
 * Notes:
 * - Callers must ensure the WebAuthn `challenge` equals `sessionPolicyDigest32`.
 * - PRF outputs must never be sent to the relay; they should be used only in wallet origin.
 */
export async function mintThresholdEd25519AuthSessionLite(args: {
  relayerUrl: string;
  sessionKind: ThresholdEd25519SessionKind;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  sessionPolicy: ThresholdEd25519SessionPolicy;
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

  type ThresholdEd25519SessionMintResponseBody = Partial<{
    ok: boolean;
    sessionId: string;
    expiresAt: string;
    remainingUses: number;
    jwt: string;
    code: string;
    message: string;
  }>;

  try {
    const url = `${relayerUrl}/threshold-ed25519/session`;
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

    const data = (await response.json().catch(() => ({}))) as ThresholdEd25519SessionMintResponseBody;
    if (!response.ok) {
      return {
        ok: false,
        code: data.code || 'http_error',
        message: data.message || `HTTP ${response.status}`,
      };
    }

    const expiresAtMs = (() => {
      const raw = data.expiresAt ? Date.parse(data.expiresAt) : NaN;
      return Number.isFinite(raw) ? raw : undefined;
    })();

    return {
      ok: data.ok === true,
      sessionId: data.sessionId,
      expiresAtMs,
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
