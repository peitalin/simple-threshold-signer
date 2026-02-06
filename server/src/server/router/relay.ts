import type { DelegateActionPolicy } from '../delegateAction';
import type { RouterLogger } from './logger';
import type { ThresholdAnySchemeModule } from '../core/ThresholdService/schemes/types';
import type { ThresholdSchemeId } from '../core/ThresholdService/schemes/schemeIds';

// Minimal session adapter interface expected by the routers.
export type SessionClaims = Record<string, unknown>;

export type SessionKind = 'cookie' | 'jwt';

export function parseSessionKind(body: unknown): SessionKind {
  const v = (body && typeof body === 'object' && !Array.isArray(body))
    ? (body as Record<string, unknown>)
    : {};
  const raw = v.sessionKind ?? v.session_kind;
  return raw === 'cookie' ? 'cookie' : 'jwt';
}

export interface SessionAdapter {
  signJwt(sub: string, extra?: Record<string, unknown>): Promise<string>;
  parse(headers: Record<string, string | string[] | undefined>): Promise<{ ok: true; claims: SessionClaims } | { ok: false }>;
  buildSetCookie(token: string): string;
  buildClearCookie(): string;
  refresh(headers: Record<string, string | string[] | undefined>): Promise<{ ok: boolean; jwt?: string; code?: string; message?: string }>;
}

export interface ThresholdSigningAdapter {
  getSchemeModule(schemeId: ThresholdSchemeId): ThresholdAnySchemeModule | null;
}

export type ThresholdSchemeModuleById<S extends ThresholdSchemeId> = Extract<ThresholdAnySchemeModule, { schemeId: S }>;

export type ResolveThresholdSchemeResult<S extends ThresholdSchemeId> =
  | { ok: true; scheme: ThresholdSchemeModuleById<S> }
  | { ok: false; code: 'threshold_disabled' | 'not_found'; message: string };

export function resolveThresholdScheme<S extends ThresholdSchemeId>(
  threshold: ThresholdSigningAdapter | null | undefined,
  schemeId: S,
  options?: { notFoundMessage?: string },
): ResolveThresholdSchemeResult<S> {
  if (!threshold) {
    return { ok: false, code: 'threshold_disabled', message: 'Threshold signing is not configured on this server' };
  }
  const scheme = threshold.getSchemeModule(schemeId);
  if (!scheme || scheme.schemeId !== schemeId) {
    return {
      ok: false,
      code: 'not_found',
      message: options?.notFoundMessage || `threshold scheme ${schemeId} is not enabled on this server`,
    };
  }
  return { ok: true, scheme: scheme as ThresholdSchemeModuleById<S> };
}

export interface RelayRouterOptions {
  healthz?: boolean;
  readyz?: boolean;
  /**
   * Optional list(s) of CORS origins (CSV strings or literal origins).
   * Pass raw strings; the router normalizes/merges internally.
   */
  corsOrigins?: Array<string | undefined>;
  /**
   * Optional route for submitting NEP-461 SignedDelegate meta-transactions.
   * - When omitted: disabled.
   * - When set: enabled at `route`.
   * `policy` is server-controlled and is never read from the request body.
   */
  signedDelegate?: {
    route: string;
    policy?: DelegateActionPolicy;
  };
  // Optional: customize session route paths
  sessionRoutes?: { auth?: string; logout?: string };
  // Optional: pluggable session adapter
  session?: SessionAdapter | null;
  // Optional: pluggable threshold signing service
  threshold?: ThresholdSigningAdapter | null;
  // Optional logger; defaults to silent.
  logger?: RouterLogger | null;
}
