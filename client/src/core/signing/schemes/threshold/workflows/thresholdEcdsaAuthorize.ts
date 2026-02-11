import { stripTrailingSlashes, toTrimmedString } from '../../../../../../../shared/src/utils/validation';

function toDigest32Bytes(input: Uint8Array | number[]): Uint8Array | null {
  if (input instanceof Uint8Array) {
    return input.length === 32 ? input : null;
  }
  if (!Array.isArray(input)) return null;
  const bytes = Uint8Array.from(input.map((v) => Number(v)));
  return bytes.length === 32 ? bytes : null;
}

export async function authorizeThresholdEcdsaWithSession(args: {
  relayerUrl: string;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  purpose: string;
  signingDigest32: Uint8Array | number[];
  signingPayload?: unknown;
  sessionKind?: 'jwt' | 'cookie';
  thresholdSessionJwt?: string;
}): Promise<{
  ok: boolean;
  mpcSessionId?: string;
  expiresAtMs?: number;
  expiresAt?: string;
  code?: string;
  message?: string;
}> {
  const relayerUrl = stripTrailingSlashes(toTrimmedString(args.relayerUrl));
  if (!relayerUrl) {
    return { ok: false, code: 'invalid_args', message: 'Missing relayerUrl for threshold-ecdsa authorize' };
  }

  if (typeof fetch !== 'function') {
    return { ok: false, code: 'unsupported', message: 'fetch is not available for threshold-ecdsa authorize' };
  }

  const relayerKeyId = String(args.relayerKeyId || '').trim();
  if (!relayerKeyId) {
    return { ok: false, code: 'invalid_args', message: 'Missing relayerKeyId for threshold-ecdsa authorize' };
  }

  const clientVerifyingShareB64u = String(args.clientVerifyingShareB64u || '').trim();
  if (!clientVerifyingShareB64u) {
    return { ok: false, code: 'invalid_args', message: 'Missing clientVerifyingShareB64u for threshold-ecdsa authorize' };
  }

  const purpose = String(args.purpose || '').trim();
  if (!purpose) {
    return { ok: false, code: 'invalid_args', message: 'Missing purpose for threshold-ecdsa authorize' };
  }

  const signingDigest32 = toDigest32Bytes(args.signingDigest32);
  if (!signingDigest32) {
    return { ok: false, code: 'invalid_args', message: 'signingDigest32 must be 32 bytes for threshold-ecdsa authorize' };
  }

  const sessionKind: 'jwt' | 'cookie' = args.sessionKind || 'jwt';
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (sessionKind === 'jwt') {
    const jwt = String(args.thresholdSessionJwt || '').trim();
    if (!jwt) {
      return { ok: false, code: 'invalid_args', message: 'Missing thresholdSessionJwt for threshold-ecdsa authorize (jwt sessionKind)' };
    }
    headers.Authorization = `Bearer ${jwt}`;
  }

  type ThresholdEcdsaAuthorizeResponseBody = Partial<{
    ok: boolean;
    mpcSessionId: string;
    expiresAt: string;
    code: string;
    message: string;
  }>;

  try {
    const url = `${relayerUrl}/threshold-ecdsa/authorize`;
    const response = await fetch(url, {
      method: 'POST',
      headers,
      credentials: sessionKind === 'cookie' ? 'include' : 'omit',
      body: JSON.stringify({
        relayerKeyId,
        clientVerifyingShareB64u,
        purpose,
        signing_digest_32: Array.from(signingDigest32),
        ...(args.signingPayload !== undefined ? { signingPayload: args.signingPayload } : {}),
      }),
    });

    const data = (await response.json().catch(() => ({}))) as ThresholdEcdsaAuthorizeResponseBody;
    if (!response.ok) {
      return {
        ok: false,
        code: data.code || 'http_error',
        message: data.message || `HTTP ${response.status}`,
      };
    }

    const expiresAtMs = (() => {
      const raw = typeof data.expiresAt === 'string' ? Date.parse(data.expiresAt) : NaN;
      return Number.isFinite(raw) ? raw : undefined;
    })();

    return {
      ok: data.ok === true,
      mpcSessionId: data.mpcSessionId,
      ...(data.expiresAt ? { expiresAt: data.expiresAt } : {}),
      ...(expiresAtMs ? { expiresAtMs } : {}),
      ...(data.code ? { code: data.code } : {}),
      ...(data.message ? { message: data.message } : {}),
    };
  } catch (e: unknown) {
    const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || 'Failed to authorize threshold-ecdsa');
    return { ok: false, code: 'network_error', message: msg };
  }
}
