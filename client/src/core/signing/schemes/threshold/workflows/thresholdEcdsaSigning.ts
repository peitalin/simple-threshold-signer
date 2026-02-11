import { base64UrlEncode } from '../../../../../../../shared/src/utils/encoders';
import { stripTrailingSlashes, toTrimmedString } from '../../../../../../../shared/src/utils/validation';

type ThresholdEcdsaSessionKind = 'jwt' | 'cookie';

type ThresholdEcdsaAuth = {
  sessionKind?: ThresholdEcdsaSessionKind;
  thresholdSessionJwt?: string;
};

function resolveRelayerUrl(input: string): string | null {
  const relayerUrl = stripTrailingSlashes(toTrimmedString(input));
  return relayerUrl || null;
}

function resolvePresignAuthHeaders(args: ThresholdEcdsaAuth): {
  ok: true;
  sessionKind: ThresholdEcdsaSessionKind;
  headers: Record<string, string>;
} | {
  ok: false;
  code: string;
  message: string;
} {
  const sessionKind: ThresholdEcdsaSessionKind = args.sessionKind || 'jwt';
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (sessionKind === 'jwt') {
    const jwt = String(args.thresholdSessionJwt || '').trim();
    if (!jwt) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Missing thresholdSessionJwt for threshold-ecdsa presign (jwt sessionKind)',
      };
    }
    headers.Authorization = `Bearer ${jwt}`;
  }
  return { ok: true, sessionKind, headers };
}

export type ThresholdEcdsaPresignProgress = {
  ok: boolean;
  code?: string;
  message?: string;
  stage?: 'triples' | 'triples_done' | 'presign' | 'done';
  event?: 'none' | 'triples_done' | 'presign_done';
  outgoingMessagesB64u?: string[];
  presignatureId?: string;
  bigRB64u?: string;
};

export async function thresholdEcdsaPresignInit(args: {
  relayerUrl: string;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  count?: number;
  sessionKind?: ThresholdEcdsaSessionKind;
  thresholdSessionJwt?: string;
}): Promise<ThresholdEcdsaPresignProgress & { presignSessionId?: string }> {
  const relayerUrl = resolveRelayerUrl(args.relayerUrl);
  if (!relayerUrl) {
    return { ok: false, code: 'invalid_args', message: 'Missing relayerUrl for threshold-ecdsa presign/init' };
  }
  if (typeof fetch !== 'function') {
    return { ok: false, code: 'unsupported', message: 'fetch is not available for threshold-ecdsa presign/init' };
  }
  const relayerKeyId = String(args.relayerKeyId || '').trim();
  if (!relayerKeyId) {
    return { ok: false, code: 'invalid_args', message: 'Missing relayerKeyId for threshold-ecdsa presign/init' };
  }
  const clientVerifyingShareB64u = String(args.clientVerifyingShareB64u || '').trim();
  if (!clientVerifyingShareB64u) {
    return { ok: false, code: 'invalid_args', message: 'Missing clientVerifyingShareB64u for threshold-ecdsa presign/init' };
  }

  const auth = resolvePresignAuthHeaders(args);
  if (!auth.ok) return auth;

  type ResponseBody = Partial<{
    ok: boolean;
    code: string;
    message: string;
    presignSessionId: string;
    stage: 'triples' | 'triples_done' | 'presign' | 'done';
    outgoingMessagesB64u: string[];
  }>;

  try {
    const response = await fetch(`${relayerUrl}/threshold-ecdsa/presign/init`, {
      method: 'POST',
      headers: auth.headers,
      credentials: auth.sessionKind === 'cookie' ? 'include' : 'omit',
      body: JSON.stringify({
        relayerKeyId,
        clientVerifyingShareB64u,
        count: Number.isFinite(args.count) ? Math.max(1, Math.floor(Number(args.count))) : 1,
      }),
    });
    const data = (await response.json().catch(() => ({}))) as ResponseBody;
    if (!response.ok) {
      return {
        ok: false,
        code: data.code || 'http_error',
        message: data.message || `HTTP ${response.status}`,
      };
    }
    return {
      ok: data.ok === true,
      presignSessionId: data.presignSessionId,
      stage: data.stage,
      outgoingMessagesB64u: Array.isArray(data.outgoingMessagesB64u) ? data.outgoingMessagesB64u : [],
      ...(data.code ? { code: data.code } : {}),
      ...(data.message ? { message: data.message } : {}),
    };
  } catch (e: unknown) {
    const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || 'Failed threshold-ecdsa presign/init');
    return { ok: false, code: 'network_error', message: msg };
  }
}

export async function thresholdEcdsaPresignStep(args: {
  relayerUrl: string;
  presignSessionId: string;
  stage: 'triples' | 'presign';
  outgoingMessagesB64u?: string[];
  sessionKind?: ThresholdEcdsaSessionKind;
  thresholdSessionJwt?: string;
}): Promise<ThresholdEcdsaPresignProgress> {
  const relayerUrl = resolveRelayerUrl(args.relayerUrl);
  if (!relayerUrl) {
    return { ok: false, code: 'invalid_args', message: 'Missing relayerUrl for threshold-ecdsa presign/step' };
  }
  if (typeof fetch !== 'function') {
    return { ok: false, code: 'unsupported', message: 'fetch is not available for threshold-ecdsa presign/step' };
  }
  const presignSessionId = String(args.presignSessionId || '').trim();
  if (!presignSessionId) {
    return { ok: false, code: 'invalid_args', message: 'Missing presignSessionId for threshold-ecdsa presign/step' };
  }

  const auth = resolvePresignAuthHeaders(args);
  if (!auth.ok) return auth;

  type ResponseBody = Partial<{
    ok: boolean;
    code: string;
    message: string;
    stage: 'triples' | 'triples_done' | 'presign' | 'done';
    event: 'none' | 'triples_done' | 'presign_done';
    outgoingMessagesB64u: string[];
    presignatureId: string;
    bigRB64u: string;
  }>;

  try {
    const response = await fetch(`${relayerUrl}/threshold-ecdsa/presign/step`, {
      method: 'POST',
      headers: auth.headers,
      credentials: auth.sessionKind === 'cookie' ? 'include' : 'omit',
      body: JSON.stringify({
        presignSessionId,
        stage: args.stage,
        outgoingMessagesB64u: Array.isArray(args.outgoingMessagesB64u) ? args.outgoingMessagesB64u : [],
      }),
    });
    const data = (await response.json().catch(() => ({}))) as ResponseBody;
    if (!response.ok) {
      return {
        ok: false,
        code: data.code || 'http_error',
        message: data.message || `HTTP ${response.status}`,
      };
    }
    return {
      ok: data.ok === true,
      stage: data.stage,
      event: data.event,
      outgoingMessagesB64u: Array.isArray(data.outgoingMessagesB64u) ? data.outgoingMessagesB64u : [],
      ...(data.presignatureId ? { presignatureId: data.presignatureId } : {}),
      ...(data.bigRB64u ? { bigRB64u: data.bigRB64u } : {}),
      ...(data.code ? { code: data.code } : {}),
      ...(data.message ? { message: data.message } : {}),
    };
  } catch (e: unknown) {
    const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || 'Failed threshold-ecdsa presign/step');
    return { ok: false, code: 'network_error', message: msg };
  }
}

export async function thresholdEcdsaSignInit(args: {
  relayerUrl: string;
  mpcSessionId: string;
  relayerKeyId: string;
  signingDigest32: Uint8Array;
  presignatureId?: string;
}): Promise<{
  ok: boolean;
  code?: string;
  message?: string;
  signingSessionId?: string;
  relayerRound1?: {
    presignatureId?: string;
    entropyB64u?: string;
    bigRB64u?: string;
  };
}> {
  const relayerUrl = resolveRelayerUrl(args.relayerUrl);
  if (!relayerUrl) {
    return { ok: false, code: 'invalid_args', message: 'Missing relayerUrl for threshold-ecdsa sign/init' };
  }
  if (typeof fetch !== 'function') {
    return { ok: false, code: 'unsupported', message: 'fetch is not available for threshold-ecdsa sign/init' };
  }

  const mpcSessionId = String(args.mpcSessionId || '').trim();
  if (!mpcSessionId) {
    return { ok: false, code: 'invalid_args', message: 'Missing mpcSessionId for threshold-ecdsa sign/init' };
  }
  const relayerKeyId = String(args.relayerKeyId || '').trim();
  if (!relayerKeyId) {
    return { ok: false, code: 'invalid_args', message: 'Missing relayerKeyId for threshold-ecdsa sign/init' };
  }
  if (!(args.signingDigest32 instanceof Uint8Array) || args.signingDigest32.length !== 32) {
    return { ok: false, code: 'invalid_args', message: 'signingDigest32 must be 32 bytes for threshold-ecdsa sign/init' };
  }

  type ResponseBody = Partial<{
    ok: boolean;
    code: string;
    message: string;
    signingSessionId: string;
    relayerRound1: {
      presignatureId?: string;
      entropyB64u?: string;
      bigRB64u?: string;
    };
  }>;

  try {
    const response = await fetch(`${relayerUrl}/threshold-ecdsa/sign/init`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mpcSessionId,
        relayerKeyId,
        signingDigestB64u: base64UrlEncode(args.signingDigest32),
        ...(args.presignatureId
          ? { clientRound1: { presignatureId: String(args.presignatureId).trim() } }
          : {}),
      }),
    });
    const data = (await response.json().catch(() => ({}))) as ResponseBody;
    if (!response.ok) {
      return {
        ok: false,
        code: data.code || 'http_error',
        message: data.message || `HTTP ${response.status}`,
      };
    }
    return {
      ok: data.ok === true,
      signingSessionId: data.signingSessionId,
      relayerRound1: data.relayerRound1,
      ...(data.code ? { code: data.code } : {}),
      ...(data.message ? { message: data.message } : {}),
    };
  } catch (e: unknown) {
    const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || 'Failed threshold-ecdsa sign/init');
    return { ok: false, code: 'network_error', message: msg };
  }
}

export async function thresholdEcdsaSignFinalize(args: {
  relayerUrl: string;
  signingSessionId: string;
  clientSignatureShare32: Uint8Array;
}): Promise<{
  ok: boolean;
  code?: string;
  message?: string;
  relayerRound2?: {
    signature65B64u?: string;
    rB64u?: string;
    sB64u?: string;
    recId?: number;
  };
}> {
  const relayerUrl = resolveRelayerUrl(args.relayerUrl);
  if (!relayerUrl) {
    return { ok: false, code: 'invalid_args', message: 'Missing relayerUrl for threshold-ecdsa sign/finalize' };
  }
  if (typeof fetch !== 'function') {
    return { ok: false, code: 'unsupported', message: 'fetch is not available for threshold-ecdsa sign/finalize' };
  }

  const signingSessionId = String(args.signingSessionId || '').trim();
  if (!signingSessionId) {
    return { ok: false, code: 'invalid_args', message: 'Missing signingSessionId for threshold-ecdsa sign/finalize' };
  }
  if (!(args.clientSignatureShare32 instanceof Uint8Array) || args.clientSignatureShare32.length !== 32) {
    return { ok: false, code: 'invalid_args', message: 'clientSignatureShare32 must be 32 bytes for threshold-ecdsa sign/finalize' };
  }

  type ResponseBody = Partial<{
    ok: boolean;
    code: string;
    message: string;
    relayerRound2: {
      signature65B64u?: string;
      rB64u?: string;
      sB64u?: string;
      recId?: number;
    };
  }>;

  try {
    const response = await fetch(`${relayerUrl}/threshold-ecdsa/sign/finalize`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        signingSessionId,
        clientRound2: {
          clientSignatureShareB64u: base64UrlEncode(args.clientSignatureShare32),
        },
      }),
    });
    const data = (await response.json().catch(() => ({}))) as ResponseBody;
    if (!response.ok) {
      return {
        ok: false,
        code: data.code || 'http_error',
        message: data.message || `HTTP ${response.status}`,
      };
    }
    return {
      ok: data.ok === true,
      relayerRound2: data.relayerRound2,
      ...(data.code ? { code: data.code } : {}),
      ...(data.message ? { message: data.message } : {}),
    };
  } catch (e: unknown) {
    const msg = String((e && typeof e === 'object' && 'message' in e) ? (e as { message?: unknown }).message : e || 'Failed threshold-ecdsa sign/finalize');
    return { ok: false, code: 'network_error', message: msg };
  }
}
