export type ThresholdRouteResult = { ok: boolean; code?: string };

export type ThresholdEd25519RouteResult = ThresholdRouteResult;
export type ThresholdEcdsaRouteResult = ThresholdRouteResult;

export function thresholdStatusCode(result: ThresholdRouteResult): number {
  if (result.ok) return 200;
  switch (result.code) {
    case 'not_found':
      return 404;
    case 'not_implemented':
      return 501;
    case 'sessions_disabled':
      return 501;
    case 'threshold_disabled':
      return 503;
    case 'pool_empty':
      return 503;
    case 'internal':
      return 500;
    case 'unauthorized':
      return 401;
    default:
      return 400;
  }
}

export function thresholdEd25519StatusCode(result: ThresholdEd25519RouteResult): number {
  return thresholdStatusCode(result);
}

export function thresholdEcdsaStatusCode(result: ThresholdEcdsaRouteResult): number {
  return thresholdStatusCode(result);
}
