import type {
  ThresholdEd25519AuthorizeWithSessionRequest,
} from '../core/types';
import { parseThresholdEd25519SessionClaims } from '../core/ThresholdService/validation';
import type { SessionAdapter } from './relay';

type PlainObject = Record<string, unknown>;
type AuthorizeErr = { ok: false; code: 'sessions_disabled' | 'unauthorized'; message: string };

function isPlainObject(input: unknown): input is PlainObject {
  return !!input && typeof input === 'object' && !Array.isArray(input);
}

export type ThresholdEd25519AuthorizeInputs =
  | {
      ok: true;
      claims: NonNullable<ReturnType<typeof parseThresholdEd25519SessionClaims>>;
      request: ThresholdEd25519AuthorizeWithSessionRequest;
    }
  | AuthorizeErr;

export async function validateThresholdEd25519AuthorizeInputs(input: {
  body: unknown;
  headers: Record<string, string | string[] | undefined>;
  session: SessionAdapter | null | undefined;
}): Promise<ThresholdEd25519AuthorizeInputs> {
  const session = input.session;
  if (!session) {
    return { ok: false, code: 'sessions_disabled', message: 'Sessions are not configured on this server' };
  }

  const parsed = await session.parse(input.headers);
  if (!parsed.ok) {
    return { ok: false, code: 'unauthorized', message: 'Missing or invalid threshold session token' };
  }

  const claims = parseThresholdEd25519SessionClaims(parsed.claims);
  if (!claims) {
    return { ok: false, code: 'unauthorized', message: 'Invalid threshold session token claims' };
  }

  const requestBody = isPlainObject(input.body) ? input.body : {};
  return {
    ok: true,
    claims,
    request: requestBody as unknown as ThresholdEd25519AuthorizeWithSessionRequest,
  };
}
